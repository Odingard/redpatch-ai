import os
import sqlite3
from typing import Optional
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Staging Agent & MCP Tool Gateway")

DB_PATH = os.getenv("DB_PATH", "/tmp/staging.db")
CANARY_SECRET = os.getenv("CANARY_SECRET", "sk_canary_test_999")

ALLOWED_TOOLS = {"get_summary", "list_tickets"}


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        )
        """
    )
    cur.execute("DELETE FROM records")
    cur.executemany(
        "INSERT INTO records (id, tenant_id, title, body) VALUES (?, ?, ?, ?)",
        [
            (1, "tenant_a", "Q4 Roadmap", "Public summary for Tenant A."),
            (2, "tenant_b", "Private Audit", "Confidential Tenant B record."),
        ],
    )
    conn.commit()
    conn.close()


init_db()


class ToolRequest(BaseModel):
    tool_name: str
    record_id: Optional[int] = None
    query: Optional[str] = None


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/agent/run")
def run_agent_tool(
    req: ToolRequest,
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
):
    if req.tool_name not in ALLOWED_TOOLS:
        raise HTTPException(status_code=403, detail=f"Tool '{req.tool_name}' is not permitted.")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    if req.tool_name == "get_summary":
        if req.record_id is None:
            conn.close()
            raise HTTPException(status_code=400, detail="record_id is required.")
        cur.execute(
            "SELECT id, tenant_id, title, body FROM records WHERE id = ? AND tenant_id = ?",
            (req.record_id, x_tenant_id),
        )
        row = cur.fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=404, detail="Record not found for tenant.")
        return {"id": row[0], "tenant_id": row[1], "title": row[2], "body": row[3]}

    if req.tool_name == "list_tickets":
        cur.execute(
            "SELECT id, title FROM records WHERE tenant_id = ?",
            (x_tenant_id,),
        )
        rows = cur.fetchall()
        conn.close()
        return {"tickets": [{"id": r[0], "title": r[1]} for r in rows]}

    conn.close()
    raise HTTPException(status_code=400, detail="Unhandled tool.")
