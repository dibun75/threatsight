from enum import StrEnum


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class ControlSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class LifecycleStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class RequirementStatus(StrEnum):
    CANDIDATE = "candidate"
    APPROVED = "approved"
    REJECTED = "rejected"
    DEFERRED = "deferred"
    EDITED = "edited"


RequirementReviewStatus = RequirementStatus


class RequirementSourceType(StrEnum):
    MANUAL = "manual"
    POLICY = "policy"
    REGULATION = "regulation"
    STANDARD = "standard"
    CONTRACT = "contract"
    DOCUMENT = "document"


class AssuranceStatus(StrEnum):
    VALIDATED = "VALIDATED"
    PARTIALLY_VALIDATED = "PARTIALLY_VALIDATED"
    GAP_DETECTED = "GAP_DETECTED"
    EVIDENCE_REQUIRED = "EVIDENCE_REQUIRED"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EvidenceType(StrEnum):
    MANUAL = "manual"
    OBSERVATION = "observation"
    DOCUMENT = "document"
    TEST_ARTIFACT = "test_artifact"
    OTHER = "other"


class EvidenceStatus(StrEnum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class EvidenceFreshness(StrEnum):
    FRESH = "FRESH"
    STALE = "STALE"
    UNTESTED = "UNTESTED"


class ReviewDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    DEFER = "defer"
    REQUEST_CHANGES = "request_changes"


class ReviewableEntity(StrEnum):
    REQUIREMENT = "requirement"
    CONTROL = "control"
    MAPPING = "mapping"
    EVIDENCE = "evidence"
    CANDIDATE = "candidate"
    DISCOVERY_SIGNAL = "discovery_signal"


class AuditAction(StrEnum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    MAP = "map"
    UNMAP = "unmap"
    REVIEW = "review"
    STATUS_CHANGE = "status_change"
    EXTRACT = "extract"
    VERSION = "version"
    EXECUTE = "execute"
    REMEDIATE = "remediate"
    RETEST = "retest"
    DISCOVER = "discover"
    SCAN = "scan"


class DocumentStatus(StrEnum):
    PROCESSING = "processing"
    READY = "ready"
    FAILED = "failed"


class ExtractionStatus(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class CandidateType(StrEnum):
    REQUIREMENT = "requirement"
    CONTROL = "control"
    EVIDENCE_STATEMENT = "evidence_statement"
    AI_SYSTEM_REFERENCE = "ai_system_reference"


class CandidateReviewStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_REVISION = "needs_revision"


class MappingProposalAction(StrEnum):
    LINK_EXISTING = "link_existing"
    PROPOSE_NEW = "propose_new"
    REJECT = "reject"


class FrameworkKey(StrEnum):
    EU_AI_ACT = "eu_ai_act"
    GDPR = "gdpr"
    NIST_AI_RMF = "nist_ai_rmf"
    ISO_42001 = "iso_42001"
    OWASP_GENAI = "owasp_genai"
    MITRE_ATLAS = "mitre_atlas"


class RecordOrigin(StrEnum):
    SHOWCASE = "showcase"
    TEST = "test"
    MANUAL = "manual"
    IMPORTED = "imported"
    OBSERVED = "observed"
