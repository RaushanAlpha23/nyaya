# M1 schema design (v1, 2026-11-04)

Status legend: DECIDED = reviewed, agreed, and ready to defend.

---

## Part 1. Whole domain (rough)

```mermaid
erDiagram
    TENANT ||--o{ USER : has
    TENANT ||--o{ DOCUMENT : owns
    TENANT ||--o{ CLAIM : owns
    TENANT ||--o{ TICKET : owns
    TENANT ||--o{ AUDIT_LOG : records
    DOCUMENT ||--o{ VERSION : "has versions"
    VERSION |o--o| VERSION : supersedes
    VERSION ||--o{ CLAUSE : contains
    CLAUSE ||--o{ REFERENCE : "source of"
    CLAUSE ||--o{ REFERENCE : "target of"
    CLAIM }o--|| VERSION : "adjudicated under"
    CLAIM ||--o{ DECISION : has
    DECISION ||--o{ APPROVAL : requires
    USER ||--o{ APPROVAL : "gives or refuses"
    TICKET }o--o| CLAIM : "raised from"