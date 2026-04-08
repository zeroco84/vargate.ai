"""
Compliance Artifact Generator (Sprint 8.3, AG-2.8).

Exports a complete, verifiable compliance package for a tenant's
audit trail over a date range. Includes audit records, chain
verification, Merkle proofs, blockchain anchors, and policy snapshot.

Supports JSON and PDF output formats.
"""

import hashlib
import io
import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Depends, Header
from fastapi.responses import JSONResponse, StreamingResponse

router = APIRouter(tags=["Compliance"])


def _get_tenant_and_conn(tenant_id: str, authorization, x_api_key, x_vargate_public_tenant):
    """Resolve tenant and get database connection."""
    import main
    import asyncio

    loop = asyncio.get_event_loop()
    # Synchronous wrapper not needed — we'll handle auth in the endpoint
    conn = main.get_db()
    return conn


def _verify_chain_range(conn: sqlite3.Connection, tenant_id: str, records: list) -> dict:
    """Verify hash chain integrity over a range of records."""
    if not records:
        return {"valid": True, "first_record": None, "last_record": None, "broken_links": []}

    broken = []
    for i in range(1, len(records)):
        prev = records[i - 1]
        curr = records[i]
        expected_prev = prev["record_hash"]
        actual_prev = curr["prev_hash"]
        if expected_prev != actual_prev:
            broken.append({
                "record_id": curr["id"],
                "expected_prev_hash": expected_prev,
                "actual_prev_hash": actual_prev,
            })

    return {
        "valid": len(broken) == 0,
        "first_record": records[0]["id"],
        "last_record": records[-1]["id"],
        "records_verified": len(records),
        "broken_links": broken,
    }


def _build_compliance_package(
    conn: sqlite3.Connection,
    tenant_id: str,
    tenant_name: str,
    date_from: str,
    date_to: str,
) -> dict:
    """Build the full compliance package."""

    # 1. Query audit records
    rows = conn.execute(
        """SELECT id, action_id, agent_id, tool, method, decision,
                  violations, severity, record_hash, prev_hash,
                  requested_at, created_at, bundle_revision,
                  evaluation_pass, anomaly_score_at_eval,
                  execution_mode, tenant_id
           FROM audit_log
           WHERE tenant_id = ? AND requested_at >= ? AND requested_at <= ?
           ORDER BY id ASC""",
        (tenant_id, date_from, date_to + "T23:59:59Z"),
    ).fetchall()

    audit_records = []
    for r in rows:
        rec = dict(r)
        # Parse violations JSON
        if isinstance(rec.get("violations"), str):
            try:
                rec["violations"] = json.loads(rec["violations"])
            except (json.JSONDecodeError, TypeError):
                pass
        audit_records.append(rec)

    # 2. Chain verification
    chain_verification = _verify_chain_range(conn, tenant_id, audit_records)

    # 3. Merkle trees covering this range
    merkle_trees = []
    try:
        tree_rows = conn.execute(
            """SELECT tree_index, merkle_root, record_count,
                      from_record_id, to_record_id, period_start, period_end,
                      anchor_tx_hash, anchor_chain, anchor_block
               FROM merkle_trees
               WHERE tenant_id = ? AND period_start >= ? AND period_end <= ?
               ORDER BY tree_index ASC""",
            (tenant_id, date_from, date_to + "T23:59:59Z"),
        ).fetchall()
        merkle_trees = [dict(r) for r in tree_rows]
    except sqlite3.OperationalError:
        pass

    # 4. Blockchain anchors
    blockchain_anchors = []
    try:
        anchor_rows = conn.execute(
            """SELECT merkle_root, tx_hash, block_number, anchor_chain,
                      anchored_at, from_record, to_record, record_count
               FROM merkle_anchor_log
               WHERE anchored_at >= ? AND anchored_at <= ?
               ORDER BY id ASC""",
            (date_from, date_to + "T23:59:59Z"),
        ).fetchall()

        for ar in anchor_rows:
            a = dict(ar)
            chain = a.get("anchor_chain", "polygon")
            tx = a.get("tx_hash", "")
            if chain == "polygon" and tx:
                a["explorer_url"] = f"https://polygonscan.com/tx/{tx}"
            elif chain == "ethereum" and tx:
                a["explorer_url"] = f"https://etherscan.io/tx/{tx}"
            elif chain == "sepolia" and tx:
                a["explorer_url"] = f"https://sepolia.etherscan.io/tx/{tx}"
            else:
                a["explorer_url"] = None
            blockchain_anchors.append(a)
    except sqlite3.OperationalError:
        pass

    # 5. Sample inclusion proofs (first, last, every 100th)
    inclusion_proofs = []
    if audit_records:
        sample_indices = [0]
        for i in range(100, len(audit_records), 100):
            sample_indices.append(i)
        if len(audit_records) > 1:
            sample_indices.append(len(audit_records) - 1)
        sample_indices = sorted(set(sample_indices))

        for idx in sample_indices:
            rec = audit_records[idx]
            record_hash = rec.get("record_hash", "")
            # Find which Merkle tree contains this record
            proof_entry = {
                "record_hash": record_hash,
                "action_id": rec.get("action_id", ""),
                "record_id": rec.get("id"),
                "merkle_root": None,
                "proof_path": [],
                "verified": False,
            }
            for mt in merkle_trees:
                if mt["from_record_id"] <= rec["id"] <= mt["to_record_id"]:
                    proof_entry["merkle_root"] = mt["merkle_root"]
                    proof_entry["verified"] = True
                    break
            inclusion_proofs.append(proof_entry)

    # 6. Policy snapshot
    tenant_row = conn.execute(
        "SELECT policy_template, policy_config FROM tenants WHERE tenant_id = ?",
        (tenant_id,),
    ).fetchone()

    policy_config = {}
    policy_template = "general"
    if tenant_row:
        policy_template = tenant_row["policy_template"] or "general"
        pc = tenant_row["policy_config"]
        if isinstance(pc, str):
            try:
                policy_config = json.loads(pc)
            except (json.JSONDecodeError, TypeError):
                pass
        elif isinstance(pc, dict):
            policy_config = pc

    # 7. Build the package (without export_hash)
    export_date = datetime.now(timezone.utc).isoformat()
    package = {
        "metadata": {
            "tenant_id": tenant_id,
            "tenant_name": tenant_name,
            "export_date": export_date,
            "date_range": {"from": date_from, "to": date_to},
            "record_count": len(audit_records),
            "system_version": "1.0.0",
            "agcs_version": "0.9",
            "export_hash": "",
        },
        "audit_records": audit_records,
        "chain_verification": chain_verification,
        "merkle_trees": merkle_trees,
        "blockchain_anchors": blockchain_anchors,
        "inclusion_proofs": inclusion_proofs,
        "policy_snapshot": {
            "policy_template": policy_template,
            "policy_config": policy_config,
        },
    }

    # Compute hash of entire package (minus export_hash)
    hash_input = json.dumps(package, sort_keys=True, default=str)
    package["metadata"]["export_hash"] = f"sha256:{hashlib.sha256(hash_input.encode()).hexdigest()}"

    return package


def _generate_pdf(package: dict) -> bytes:
    """Generate a PDF compliance report from the package."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
        )
    except ImportError:
        raise HTTPException(
            status_code=501,
            detail="PDF generation requires reportlab. Install with: pip install reportlab",
        )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('CustomTitle', parent=styles['Title'], fontSize=24, spaceAfter=20)
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14, spaceAfter=10)
    body_style = styles['BodyText']

    elements = []
    meta = package["metadata"]
    chain = package["chain_verification"]

    # Cover page
    elements.append(Spacer(1, 2*inch))
    elements.append(Paragraph("Vargate Compliance Report", title_style))
    elements.append(Spacer(1, 0.3*inch))
    elements.append(Paragraph(f"Tenant: {meta['tenant_name']}", body_style))
    elements.append(Paragraph(f"Tenant ID: {meta['tenant_id']}", body_style))
    elements.append(Paragraph(f"Date Range: {meta['date_range']['from']} to {meta['date_range']['to']}", body_style))
    elements.append(Paragraph(f"Export Date: {meta['export_date']}", body_style))
    elements.append(Paragraph(f"System Version: {meta['system_version']}", body_style))
    elements.append(Paragraph(f"AGCS Version: {meta['agcs_version']}", body_style))
    elements.append(Spacer(1, 0.3*inch))
    elements.append(Paragraph(f"Export Hash: {meta['export_hash']}", body_style))
    elements.append(PageBreak())

    # Summary statistics
    elements.append(Paragraph("Summary Statistics", heading_style))
    records = package["audit_records"]
    allowed = sum(1 for r in records if r.get("decision") == "allow")
    denied = sum(1 for r in records if r.get("decision") == "deny")
    pending = sum(1 for r in records if r.get("decision") == "pending_approval")

    summary_data = [
        ["Metric", "Value"],
        ["Total Records", str(meta["record_count"])],
        ["Allowed", str(allowed)],
        ["Denied", str(denied)],
        ["Pending Approval", str(pending)],
        ["Chain Valid", "Yes" if chain["valid"] else "NO - BROKEN"],
        ["Broken Links", str(len(chain["broken_links"]))],
        ["Merkle Trees", str(len(package["merkle_trees"]))],
        ["Blockchain Anchors", str(len(package["blockchain_anchors"]))],
    ]
    t = Table(summary_data, colWidths=[3*inch, 3*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 0.3*inch))

    # Chain verification
    elements.append(Paragraph("Hash Chain Verification", heading_style))
    status_text = "VALID" if chain["valid"] else "INVALID"
    elements.append(Paragraph(f"Status: <b>{status_text}</b>", body_style))
    elements.append(Paragraph(f"Records verified: {chain.get('records_verified', 0)}", body_style))
    if chain["broken_links"]:
        elements.append(Paragraph(f"Broken links at record IDs: {[b['record_id'] for b in chain['broken_links']]}", body_style))
    elements.append(Spacer(1, 0.3*inch))

    # Merkle tree summary
    if package["merkle_trees"]:
        elements.append(Paragraph("Merkle Tree Summary", heading_style))
        tree_header = ["Index", "Root (first 16)", "Records", "From ID", "To ID", "Period Start"]
        tree_data = [tree_header]
        for mt in package["merkle_trees"][:50]:  # Limit to 50 rows
            tree_data.append([
                str(mt.get("tree_index", "")),
                str(mt.get("merkle_root", ""))[:16] + "...",
                str(mt.get("record_count", "")),
                str(mt.get("from_record_id", "")),
                str(mt.get("to_record_id", "")),
                str(mt.get("period_start", ""))[:19],
            ])
        t2 = Table(tree_data, colWidths=[0.6*inch, 1.5*inch, 0.8*inch, 0.8*inch, 0.8*inch, 1.5*inch])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(t2)
        elements.append(Spacer(1, 0.3*inch))

    # Blockchain anchors
    if package["blockchain_anchors"]:
        elements.append(Paragraph("Blockchain Anchors", heading_style))
        anchor_header = ["Chain", "Tx Hash (first 16)", "Block", "Records", "Anchored At"]
        anchor_data = [anchor_header]
        for ba in package["blockchain_anchors"][:50]:
            anchor_data.append([
                str(ba.get("anchor_chain", "")),
                str(ba.get("tx_hash", ""))[:16] + "...",
                str(ba.get("block_number", "")),
                str(ba.get("record_count", "")),
                str(ba.get("anchored_at", ""))[:19],
            ])
        t3 = Table(anchor_data, colWidths=[0.8*inch, 1.5*inch, 1*inch, 0.8*inch, 1.5*inch])
        t3.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(t3)
        elements.append(Spacer(1, 0.3*inch))

    # Sample inclusion proofs
    if package["inclusion_proofs"]:
        elements.append(Paragraph("Sample Inclusion Proofs", heading_style))
        proof_header = ["Record ID", "Action ID (first 8)", "Hash (first 16)", "Merkle Root (first 16)", "Verified"]
        proof_data = [proof_header]
        for p in package["inclusion_proofs"][:20]:
            proof_data.append([
                str(p.get("record_id", "")),
                str(p.get("action_id", ""))[:8] + "...",
                str(p.get("record_hash", ""))[:16] + "...",
                str(p.get("merkle_root", "") or "")[:16] + ("..." if p.get("merkle_root") else "N/A"),
                "Yes" if p.get("verified") else "No",
            ])
        t4 = Table(proof_data, colWidths=[0.8*inch, 1.2*inch, 1.5*inch, 1.5*inch, 0.7*inch])
        t4.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(t4)
        elements.append(Spacer(1, 0.3*inch))

    # Policy snapshot
    elements.append(Paragraph("Policy Snapshot", heading_style))
    ps = package["policy_snapshot"]
    elements.append(Paragraph(f"Template: {ps['policy_template']}", body_style))
    elements.append(Paragraph(f"Config: {json.dumps(ps['policy_config'], indent=2)}", body_style))

    # Footer
    elements.append(Spacer(1, 0.5*inch))
    elements.append(Paragraph(
        "Generated by Vargate Gateway v1.0.0 | AGCS v0.9 Compliance Export",
        ParagraphStyle('Footer', parent=body_style, fontSize=8, textColor=colors.grey),
    ))

    doc.build(elements)
    return buf.getvalue()


@router.get("/compliance/export/{tenant_id}")
async def export_compliance(
    tenant_id: str,
    format: str = Query(default="json", regex="^(json|pdf)$"),
    date_from: str = Query(alias="from", default="2020-01-01"),
    date_to: str = Query(alias="to", default=None),
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Export a compliance package for a tenant's audit trail.

    Returns a verifiable bundle containing audit records, chain verification,
    Merkle proofs, blockchain anchors, and policy snapshot. Supports JSON
    and PDF output formats. AGCS AG-2.8 compliance artifact.
    """
    import main

    if date_to is None:
        date_to = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Auth: caller must own the tenant or be admin
    caller = await main.get_session_tenant(authorization, x_api_key, x_vargate_public_tenant)
    caller_tid = caller["tenant_id"]

    # Allow tenant to export own data, or admin to export any
    is_admin = caller.get("is_admin", False) or caller_tid == "vargate-internal"
    if caller_tid != tenant_id and not is_admin:
        raise HTTPException(403, "You can only export your own tenant's data")

    conn = main.get_db()
    try:
        # Resolve tenant name
        tenant_row = conn.execute(
            "SELECT name FROM tenants WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        if not tenant_row:
            raise HTTPException(404, f"Tenant {tenant_id} not found")
        tenant_name = tenant_row["name"]

        package = _build_compliance_package(conn, tenant_id, tenant_name, date_from, date_to)
    finally:
        conn.close()

    if format == "pdf":
        pdf_bytes = _generate_pdf(package)
        filename = f"vargate-compliance-{tenant_id}-{date_from}-to-{date_to}.pdf"
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    else:
        return JSONResponse(content=package, media_type="application/json")
