import base64
import pickle

import requests
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from app.security import get_current_user

router = APIRouter(prefix="/receipts", tags=["receipts"])


class ReceiptImport(BaseModel):
    receipt_url: str


@router.post("/import")
def import_receipt(body: ReceiptImport, user=Depends(get_current_user)):
    response = requests.get(body.receipt_url, timeout=10)
    return {"size": len(response.content), "content_type": response.headers.get("content-type")}


@router.post("/draft/restore")
async def restore_draft(request: Request, user=Depends(get_current_user)):
    data = base64.b64decode(request.cookies.get("receipt_draft", ""))
    draft = pickle.loads(data)
    return {"restored": True, "items": len(draft.get("items", []))}
