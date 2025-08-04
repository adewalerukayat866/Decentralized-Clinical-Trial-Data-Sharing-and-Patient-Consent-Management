;; Data Integrity Verification Contract
;; Ensures accuracy and reliability of clinical trial data through cryptographic hashing

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u300))
(define-constant ERR-DATA-NOT-FOUND (err u301))
(define-constant ERR-HASH-MISMATCH (err u302))
(define-constant ERR-INVALID-INPUT (err u303))
(define-constant ERR-VERIFICATION-FAILED (err u304))

;; Data structures
(define-map data-records
  { record-id: (buff 32) }
  {
    data-hash: (buff 32),
    metadata-hash: (buff 32),
    study-id: (string-ascii 50),
    record-type: (string-ascii 50),
    created-timestamp: uint,
    created-by: principal,
    verification-status: (string-ascii 20),
    last-verified: (optional uint)
  }
)

(define-map verification-history
  { record-id: (buff 32), verification-id: uint }
  {
    verifier: principal,
    verification-timestamp: uint,
    verification-result: bool,
    verification-method: (string-ascii 100),
    notes: (string-ascii 300)
  }
)

(define-map data-modifications
  { modification-id: uint }
  {
    record-id: (buff 32),
    old-hash: (buff 32),
    new-hash: (buff 32),
    modified-by: principal,
    modification-timestamp: uint,
    modification-reason: (string-ascii 200),
    approved-by: (optional principal)
  }
)

(define-map authorized-verifiers
  { verifier: principal }
  {
    role: (string-ascii 30),
    institution: (string-ascii 100),
    active: bool,
    authorized-by: principal
  }
)

;; Counters
(define-data-var next-verification-id uint u1)
(define-data-var next-modification-id uint u1)
(define-data-var contract-owner principal tx-sender)

;; Initialize contract owner as authorized verifier
(map-set authorized-verifiers
  { verifier: tx-sender }
  {
    role: "administrator",
    institution: "system",
    active: true,
    authorized-by: tx-sender
  }
)

;; Authorization checks
(define-private (is-authorized-verifier (user principal))
  (match (map-get? authorized-verifiers { verifier: user })
    verifier-data (get active verifier-data)
    false
  )
)

(define-private (is-admin (user principal))
  (is-eq user (var-get contract-owner))
)

;; Add authorized verifier
(define-public (add-authorized-verifier
  (verifier principal)
  (role (string-ascii 30))
  (institution (string-ascii 100))
)
  (begin
    (asserts! (is-admin tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (> (len role) u0) ERR-INVALID-INPUT)
    (asserts! (> (len institution) u0) ERR-INVALID-INPUT)

    (ok (map-set authorized-verifiers
      { verifier: verifier }
      {
        role: role,
        institution: institution,
        active: true,
        authorized-by: tx-sender
      }
    ))
  )
)

;; Create data record
(define-public (create-data-record
  (record-id (buff 32))
  (data-hash (buff 32))
  (metadata-hash (buff 32))
  (study-id (string-ascii 50))
  (record-type (string-ascii 50))
)
  (begin
    (asserts! (is-authorized-verifier tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (> (len record-id) u0) ERR-INVALID-INPUT)
    (asserts! (> (len data-hash) u0) ERR-INVALID-INPUT)
    (asserts! (> (len study-id) u0) ERR-INVALID-INPUT)

    (ok (map-set data-records
      { record-id: record-id }
      {
        data-hash: data-hash,
        metadata-hash: metadata-hash,
        study-id: study-id,
        record-type: record-type,
        created-timestamp: block-height,
        created-by: tx-sender,
        verification-status: "pending",
        last-verified: none
      }
    ))
  )
)

;; Verify data integrity
(define-public (verify-data-integrity
  (record-id (buff 32))
  (provided-hash (buff 32))
  (verification-method (string-ascii 100))
  (notes (string-ascii 300))
)
  (let (
    (record-data (unwrap! (map-get? data-records { record-id: record-id }) ERR-DATA-NOT-FOUND))
    (verification-id (var-get next-verification-id))
    (current-block-height block-height)
    (hash-matches (is-eq (get data-hash record-data) provided-hash))
  )
    (asserts! (is-authorized-verifier tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (> (len provided-hash) u0) ERR-INVALID-INPUT)

    ;; Record verification attempt
    (map-set verification-history
      { record-id: record-id, verification-id: verification-id }
      {
        verifier: tx-sender,
        verification-timestamp: current-block-height,
        verification-result: hash-matches,
        verification-method: verification-method,
        notes: notes
      }
    )

    ;; Update record status if verification successful
    (if hash-matches
      (map-set data-records
        { record-id: record-id }
        (merge record-data {
          verification-status: "verified",
          last-verified: (some current-block-height)
        })
      )
      (map-set data-records
        { record-id: record-id }
        (merge record-data {
          verification-status: "failed"
        })
      )
    )

    (var-set next-verification-id (+ verification-id u1))
    (if hash-matches
      (ok true)
      ERR-HASH-MISMATCH
    )
  )
)

;; Record data modification
(define-public (record-data-modification
  (record-id (buff 32))
  (new-hash (buff 32))
  (modification-reason (string-ascii 200))
)
  (let (
    (record-data (unwrap! (map-get? data-records { record-id: record-id }) ERR-DATA-NOT-FOUND))
    (modification-id (var-get next-modification-id))
    (old-hash (get data-hash record-data))
  )
    (asserts! (is-authorized-verifier tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (> (len new-hash) u0) ERR-INVALID-INPUT)
    (asserts! (> (len modification-reason) u0) ERR-INVALID-INPUT)

    ;; Record the modification
    (map-set data-modifications
      { modification-id: modification-id }
      {
        record-id: record-id,
        old-hash: old-hash,
        new-hash: new-hash,
        modified-by: tx-sender,
        modification-timestamp: block-height,
        modification-reason: modification-reason,
        approved-by: none
      }
    )

    ;; Update the record with new hash
    (map-set data-records
      { record-id: record-id }
      (merge record-data {
        data-hash: new-hash,
        verification-status: "pending",
        last-verified: none
      })
    )

    (var-set next-modification-id (+ modification-id u1))
    (ok modification-id)
  )
)

;; Batch verify multiple records
(define-public (batch-verify-records (record-hashes (list 10 { record-id: (buff 32), hash: (buff 32) })))
  (let (
    (verification-results (map verify-single-record record-hashes))
  )
    (asserts! (is-authorized-verifier tx-sender) ERR-NOT-AUTHORIZED)
    (ok verification-results)
  )
)

(define-private (verify-single-record (record-hash { record-id: (buff 32), hash: (buff 32) }))
  (let (
    (record-id (get record-id record-hash))
    (provided-hash (get hash record-hash))
    (record-data (map-get? data-records { record-id: record-id }))
  )
    (match record-data
      data (is-eq (get data-hash data) provided-hash)
      false
    )
  )
)

;; Read-only functions
(define-read-only (get-data-record (record-id (buff 32)))
  (map-get? data-records { record-id: record-id })
)

(define-read-only (get-verification-history (record-id (buff 32)) (verification-id uint))
  (map-get? verification-history { record-id: record-id, verification-id: verification-id })
)

(define-read-only (get-modification-record (modification-id uint))
  (map-get? data-modifications { modification-id: modification-id })
)

(define-read-only (get-verifier-info (verifier principal))
  (map-get? authorized-verifiers { verifier: verifier })
)

(define-read-only (is-record-verified (record-id (buff 32)))
  (match (map-get? data-records { record-id: record-id })
    record-data (is-eq (get verification-status record-data) "verified")
    false
  )
)
