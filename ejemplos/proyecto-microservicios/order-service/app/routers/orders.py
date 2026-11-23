import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Order
from app.schemas import OrderCreate, OrderRead
from app.security import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/orders", tags=["orders"])


@router.get("", response_model=List[OrderRead])
def list_my_orders(limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), user=Depends(get_current_user)):
    return db.query(Order).filter(Order.user_id == user.id).order_by(Order.created_at.desc()).limit(limit).all()


@router.get("/{order_id}", response_model=OrderRead)
def get_order(order_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    order = db.query(Order).filter(Order.id == order_id).first()
    if order is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Order not found")
    return order


@router.post("", response_model=OrderRead, status_code=status.HTTP_201_CREATED)
def create_order(payload: OrderCreate, db: Session = Depends(get_db), user=Depends(get_current_user)):
    order = Order(user_id=user.id, product_id=payload.product_id, quantity=payload.quantity)
    db.add(order)
    db.commit()
    db.refresh(order)
    logger.info("order %s created for user %s", order.id, user.id)
    return order
