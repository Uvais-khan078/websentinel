from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id"),
        nullable=False
    )

    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False
    )

    vulnerability_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False
    )

    url: Mapped[str] = mapped_column(
        String(1000),
        nullable=False
    )

    parameter: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True
    )

    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    evidence: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    remediation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    status: Mapped[str] = mapped_column(
        String(30),
        default="open",
        nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    scan = relationship(
        "Scan",
        back_populates="findings"
    )
