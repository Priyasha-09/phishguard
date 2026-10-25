
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import (
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker


BASE_DIR = Path(__file__).resolve().parent.parent

# Use DATABASE_URL when configured; otherwise, use local SQLite.
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    DATABASE_PATH = BASE_DIR / "phishguard.db"
    DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"
elif DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://",
        "postgresql+psycopg://",
        1,
    )
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace(
        "postgresql://",
        "postgresql+psycopg://",
        1,
    )

# SQLite needs a special connection argument.
connect_args = (
    {"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite")
    else {}
)

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

Base = declarative_base()


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(20), nullable=False)
    input_text = Column(Text, nullable=False)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(20), nullable=False)
    result_json = Column(Text, nullable=False)

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


def save_scan(
    scan_type: str,
    input_text: str,
    result: dict,
) -> dict:
    db = SessionLocal()

    try:
        scan = ScanHistory(
            scan_type=scan_type,
            input_text=input_text,
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            result_json=json.dumps(result),
        )

        db.add(scan)
        db.commit()
        db.refresh(scan)

        return {
            "id": scan.id,
            "type": scan.scan_type,
            "input": scan.input_text,
            "score": scan.risk_score,
            "level": scan.risk_level,
            "date": scan.created_at.isoformat(),
            "data": result,
        }

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


def get_scans(limit: int = 50) -> list[dict]:
    db = SessionLocal()

    try:
        scans = (
            db.query(ScanHistory)
            .order_by(ScanHistory.id.desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "id": scan.id,
                "type": scan.scan_type,
                "input": scan.input_text,
                "score": scan.risk_score,
                "level": scan.risk_level,
                "date": scan.created_at.isoformat(),
                "data": json.loads(scan.result_json),
            }
            for scan in scans
        ]

    finally:
        db.close()


def initialize_database() -> None:
    Base.metadata.create_all(bind=engine)
