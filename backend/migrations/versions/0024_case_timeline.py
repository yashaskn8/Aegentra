"""Index case scope derived from retained audit payloads.

Revision ID: 0024_case_timeline
Revises: 0023_case_evidence_page
"""
from alembic import op
import sqlalchemy as sa


revision = "0024_case_timeline"
down_revision = "0023_case_evidence_page"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Stored coordinates keep old and new writers on the same ledger contract.
    op.execute("""
        CREATE FUNCTION public.aegentra_timeline_scope_v1(
            stream_name text, event_name text, payload bytea, payload_hash bytea
        ) RETURNS uuid[] LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog AS $$
        DECLARE
            document jsonb;
            case_ref text;
            evidence_ref text;
        BEGIN
            IF stream_name <> 'cases' OR event_name NOT IN (
                'CASE_CREATED', 'CASE_EVIDENCE_LINKED', 'INCIDENT_TRIAGED',
                'INCIDENT_CONTAINMENT_REQUESTED', 'INCIDENT_CONTAINMENT_VERIFIED'
            ) OR sha256(payload) <> payload_hash THEN
                RETURN NULL;
            END IF;
            BEGIN
                document := convert_from(payload, 'UTF8')::jsonb;
                IF document->>'kind' IS DISTINCT FROM 'aegentra.audit.payload.v2'
                    OR document->>'event_type' IS DISTINCT FROM event_name
                    OR jsonb_typeof(document->'body') IS DISTINCT FROM 'object' THEN
                    RETURN NULL;
                END IF;
                case_ref := document->'body'->>'case_id';
                IF case_ref IS NULL OR case_ref::uuid::text <> case_ref THEN
                    RETURN NULL;
                END IF;
                IF event_name = 'CASE_EVIDENCE_LINKED' THEN
                    evidence_ref := document->'body'->>'evidence_id';
                    IF evidence_ref IS NULL OR evidence_ref::uuid::text <> evidence_ref THEN
                        RETURN NULL;
                    END IF;
                END IF;
                RETURN ARRAY[case_ref::uuid, evidence_ref::uuid];
            EXCEPTION WHEN data_exception OR program_limit_exceeded THEN
                RETURN NULL;
            END;
        END;
        $$
    """)
    op.execute("""
        ALTER TABLE audit_entries
        ADD COLUMN timeline_case_id uuid GENERATED ALWAYS AS (
            (public.aegentra_timeline_scope_v1(stream, event_type, payload_bytes, body_hash))[1]
        ) STORED,
        ADD COLUMN timeline_evidence_id uuid GENERATED ALWAYS AS (
            (public.aegentra_timeline_scope_v1(stream, event_type, payload_bytes, body_hash))[2]
        ) STORED
    """)
    op.create_index(
        "ix_audit_case_timeline", "audit_entries",
        ["org_id", "timeline_case_id", "created_at", "event_hash"],
        unique=True, postgresql_where=sa.text("timeline_case_id IS NOT NULL"),
    )
    op.execute("""
        CREATE FUNCTION public.aegentra_guard_containment_audit()
        RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $$
        BEGIN
            IF current_user <> 'aegentra_incident' THEN
                RAISE EXCEPTION 'independent incident custody role required for containment audit'
                    USING ERRCODE = '42501';
            END IF;
            RETURN NEW;
        END
        $$
    """)
    op.execute("""
        CREATE TRIGGER containment_audit_custody_guard
        BEFORE INSERT ON audit_entries FOR EACH ROW
        WHEN (NEW.stream = 'cases' AND NEW.event_type = 'INCIDENT_CONTAINMENT_VERIFIED')
        EXECUTE FUNCTION public.aegentra_guard_containment_audit()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER containment_audit_custody_guard ON audit_entries")
    op.execute("DROP FUNCTION public.aegentra_guard_containment_audit()")
    op.drop_index("ix_audit_case_timeline", table_name="audit_entries")
    op.drop_column("audit_entries", "timeline_evidence_id")
    op.drop_column("audit_entries", "timeline_case_id")
    op.execute("DROP FUNCTION public.aegentra_timeline_scope_v1(text, text, bytea, bytea)")
