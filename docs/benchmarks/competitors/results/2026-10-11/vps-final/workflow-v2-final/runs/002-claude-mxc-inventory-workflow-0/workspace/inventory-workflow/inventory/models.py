from dataclasses import dataclass
from decimal import Decimal

@dataclass(frozen=True)
class Item:
    sku: str
    category: str
    quantity: int
    unit_price: Decimal
