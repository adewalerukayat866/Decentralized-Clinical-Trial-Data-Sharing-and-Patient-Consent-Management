;; Audit Trail Contract
;; Maintains verifiable records of all system activities for regulatory compliance

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u500))
(define-constant ERR-INVALID-INPUT (err u501))
(define-constant ERR-LOG-NOT-FOUND (err u502))
(define-constant ERR-INVALID-TIMESTAMP (err u503))

;; Data structures
(define-map audit-logs
  { log-id: uint }
  {
    user: principal,
    action: (string-ascii 100),
    resource-type: (string-ascii 50),
    resource-id: (string-ascii 100),
    timestamp: uint,
    ip-hash: (optional (buff 32)),
    user-agent-hash: (optional (buff 32)),
    success: bool,
    error-code: (optional uint),
    additional-data: (string-ascii 500)
  }
)

(define-map system-events
  { event-id: uint }
  {
    event-type: (string-ascii 50),
    event-description: (string-ascii 300),
    triggered-by: principal,
    timestamp: uint,
    severity: (string-ascii 20),
    affected-resources: (string-ascii 200),
    resolution-status: (string-ascii 20)
  }
)

(define-map compliance-reports
  { report-id: uint }
  {
    report-type: (string-ascii 50),
    reporting-period-start: uint,
    reporting-period-end: uint,
    generated-by: principal,
    generation-timestamp: uint,
    total-activities: uint,
    compliance-status: (string-ascii 20),
    findings: (string-ascii 1000)
  }
)

(define-map authorized-auditors
  { auditor: principal }
  {
    role: (string-ascii 30),
    permissions: (string-ascii 100),
    active: bool,
    authorized-by: principal
  }
)

;; Counters
(define-data-var next-log-id uint u1)
(define-data-var next-event-id uint u1)
(define-data-var next-report-id uint u1)
(define-data-var contract-owner principal tx-sender)

;; Initialize contract owner as authorized auditor
(map-set authorized-auditors
  { auditor: tx-sender }
  {
    role: "administrator",
    permissions: "full-access",
    active: true,
    authorized-by: tx-sender
  }
)

;; Authorization checks
(define-private (is-authorized-auditor (user principal))
  (match (map-get? authorized-auditors { auditor: user })
    auditor-data (get active auditor-data)
    false
  )
)

(define-private (is-admin (user principal))
  (is-eq user (var-get contract-owner))
)

;; Add authorized auditor
(define-public (add-authorized-auditor
  (auditor principal)
  (role (string-ascii 30))
  (permissions (string-ascii 100))
)
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (> (len role) u0) ERR-INVALID-INPUT)
    (asserts! (> (len permissions) u0) ERR-INVALID-INPUT)

    (ok (map-set authorized-auditors
      { auditor: auditor }
      {
        role: role,
        permissions: permissions,
        active: true,
        authorized-by: tx-sender
      }
    ))
  )
)

;; Log user activity
(define-public (log-activity
  (user principal)
  (action (string-ascii 100))
  (resource-type (string-ascii 50))
  (resource-id (string-ascii 100))
  (ip-hash (optional (buff 32)))
  (user-agent-hash (optional (buff 32)))
  (success bool)
  (error-code (optional uint))
  (additional-data (string-ascii 500))
)
  (let (
    (log-id (var-get next-log-id))
    (current-block-height block-height)
  )
    (asserts! (is-authorized-auditor tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (> (len action) u0) ERR-INVALID-INPUT)
    (asserts! (> (len resource-type) u0) ERR-INVALID-INPUT)

    (map-set audit-logs
      { log-id: log-id }
      {
        user: user,
        action: action,
        resource-type: resource-type,
        resource-id: resource-id,
        timestamp: current-block-height,
        ip-hash: ip-hash,
        user-agent-hash: user-agent-hash,
        success: success,
        error-code: error-code,
        additional-data: additional-data
      }
    )

    (var-set next-log-id (+ log-id u1))
    (ok log-id)
  )
)

;; Log system event
(define-public (log-system-event
  (event-type (string-ascii 50))
  (event-description (string-ascii 300))
  (severity (string-ascii 20))
  (affected-resources (string-ascii 200))
)
  (let (
    (event-id (var-get next-event-id))
    (current-block-height block-height)
  )
    (asserts! (is-authorized-auditor tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (> (len event-type) u0) ERR-INVALID-INPUT)
    (asserts! (> (len event-description) u0) ERR-INVALID-INPUT)
    (asserts! (> (len severity) u0) ERR-INVALID-INPUT)

    (map-set system-events
      { event-id: event-id }
      {
        event-type: event-type,
        event-description: event-description,
        triggered-by: tx-sender,
        timestamp: current-block-height,
        severity: severity,
        affected-resources: affected-resources,
        resolution-status: "open"
      }
    )

    (var-set next-event-id (+ event-id u1))
    (ok event-id)
  )
)

;; Generate compliance report
(define-public (generate-compliance-report
  (report-type (string-ascii 50))
  (period-start uint)
  (period-end uint)
  (findings (string-ascii 1000))
)
  (let (
    (report-id (var-get next-report-id))
    (current-block-height block-height)
    (activity-count (count-activities-in-period period-start period-end))
  )
    (asserts! (is-authorized-auditor tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (> (len report-type) u0) ERR-INVALID-INPUT)
    (asserts! (< period-start period-end) ERR-INVALID-TIMESTAMP)
    (asserts! (< period-end current-block-height) ERR-INVALID-TIMESTAMP)

    (map-set compliance-reports
      { report-id: report-id }
      {
        report-type: report-type,
        reporting-period-start: period-start,
        reporting-period-end: period-end,
        generated-by: tx-sender,
        generation-timestamp: current-block-height,
        total-activities: activity-count,
        compliance-status: "compliant",
        findings: findings
      }
    )

    (var-set next-report-id (+ report-id u1))
    (ok report-id)
  )
)

;; Helper function to count activities in period (simplified)
(define-private (count-activities-in-period (start uint) (end uint))
  ;; This is a simplified implementation
  ;; In a real system, this would iterate through logs and count activities
  u0
)

;; Resolve system event
(define-public (resolve-system-event (event-id uint))
  (let (
    (event-data (unwrap! (map-get? system-events { event-id: event-id }) ERR-LOG-NOT-FOUND))
  )
    (asserts! (is-authorized-auditor tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (is-eq (get resolution-status event-data) "open") ERR-INVALID-INPUT)

    (map-set system-events
      { event-id: event-id }
      (merge event-data {
        resolution-status: "resolved"
      })
    )
    (ok true)
  )
)

;; Batch log multiple activities
(define-public (batch-log-activities (activities (list 20 {
  user: principal,
  action: (string-ascii 100),
  resource-type: (string-ascii 50),
  resource-id: (string-ascii 100),
  success: bool
})))
  (let (
    (results (map log-single-activity activities))
  )
    (asserts! (is-authorized-auditor tx-sender) ERR-NOT-AUTHORIZED)
    (ok results)
  )
)

(define-private (log-single-activity (activity {
  user: principal,
  action: (string-ascii 100),
  resource-type: (string-ascii 50),
  resource-id: (string-ascii 100),
  success: bool
}))
  (let (
    (log-id (var-get next-log-id))
  )
    (map-set audit-logs
      { log-id: log-id }
      {
        user: (get user activity),
        action: (get action activity),
        resource-type: (get resource-type activity),
        resource-id: (get resource-id activity),
        timestamp: block-height,
        ip-hash: none,
        user-agent-hash: none,
        success: (get success activity),
        error-code: none,
        additional-data: ""
      }
    )
    (var-set next-log-id (+ log-id u1))
    log-id
  )
)

;; Read-only functions
(define-read-only (get-audit-log (log-id uint))
  (map-get? audit-logs { log-id: log-id })
)

(define-read-only (get-system-event (event-id uint))
  (map-get? system-events { event-id: event-id })
)

(define-read-only (get-compliance-report (report-id uint))
  (map-get? compliance-reports { report-id: report-id })
)

(define-read-only (get-auditor-info (auditor principal))
  (map-get? authorized-auditors { auditor: auditor })
)

(define-read-only (get-activity-count)
  (var-get next-log-id)
)

(define-read-only (get-event-count)
  (var-get next-event-id)
)

(define-read-only (get-report-count)
  (var-get next-report-id)
)
