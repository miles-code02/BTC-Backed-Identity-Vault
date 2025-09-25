;; BTC-Backed Identity Vault
;; A comprehensive decentralized identity manager for verifiable credentials
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-unauthorized (err u103))
(define-constant err-expired (err u104))
(define-constant err-invalid-amount (err u105))
(define-constant err-insufficient-funds (err u106))
(define-constant err-invalid-signature (err u107))
(define-constant err-credential-revoked (err u108))
(define-constant err-invalid-endorser (err u109))
(define-constant err-cooling-period (err u110))

(define-constant min-stake-amount u1000000) ;; 0.01 BTC in sats
(define-constant reputation-threshold u80)
(define-constant endorsement-cost u100000) ;; 0.001 BTC in sats
(define-constant cooling-period u144) ;; ~24 hours in blocks

;; Core data maps
(define-map user-credentials 
  { user: principal, credential-id: (string-ascii 64) }
  { 
    credential-hash: (buff 32),
    issuer: principal,
    issued-at: uint,
    expires-at: uint,
    verified: bool,
    revoked: bool,
    stake-amount: uint,
    endorsement-count: uint
  })

(define-map user-profile
  principal
  {
    total-credentials: uint,
    reputation-score: uint,
    created-at: uint,
    total-stake: uint,
    verified-credentials: uint,
    last-activity: uint
  })

(define-map credential-types
  (string-ascii 32)
  {
    type-name: (string-ascii 64),
    required-stake: uint,
    verification-required: bool,
    created-by: principal,
    active: bool
  })

(define-public (create-profile (initial-stake uint))
  (let ((caller tx-sender))
    (asserts! (is-none (map-get? user-profile caller)) err-already-exists)
    (asserts! (>= initial-stake min-stake-amount) err-invalid-amount)
    (try! (stx-transfer? initial-stake caller (as-contract tx-sender)))
    (ok (map-set user-profile caller {
      total-credentials: u0,
      reputation-score: u100,
      created-at: block-height,
      total-stake: initial-stake,
      verified-credentials: u0,
      last-activity: block-height
    }))))

(define-public (update-profile-activity)
  (let ((caller tx-sender))
    (let ((profile (unwrap! (map-get? user-profile caller) err-not-found)))
      (ok (map-set user-profile caller 
        (merge profile {last-activity: block-height}))))))

(define-public (add-credential 
  (credential-id (string-ascii 64))
  (credential-hash (buff 32))
  (issuer principal)
  (expires-at uint)
  (credential-type (string-ascii 32))
  (stake-amount uint))
  (let ((caller tx-sender))
    (asserts! (is-some (map-get? user-profile caller)) err-not-found)
    (asserts! (is-none (map-get? user-credentials {user: caller, credential-id: credential-id})) err-already-exists)
    (let ((cred-type (map-get? credential-types credential-type)))
      (asserts! (and (is-some cred-type) (get active (unwrap-panic cred-type))) err-not-found)
      (asserts! (>= stake-amount (get required-stake (unwrap-panic cred-type))) err-invalid-amount)
      (try! (stx-transfer? stake-amount caller (as-contract tx-sender)))
      (map-set user-credentials 
        {user: caller, credential-id: credential-id}
        {
          credential-hash: credential-hash,
          issuer: issuer,
          issued-at: block-height,
          expires-at: expires-at,
          verified: false,
          revoked: false,
          stake-amount: stake-amount,
          endorsement-count: u0
        })
      (let ((profile (unwrap! (map-get? user-profile caller) err-not-found)))
        (ok (map-set user-profile caller 
          (merge profile {
            total-credentials: (+ (get total-credentials profile) u1),
            total-stake: (+ (get total-stake profile) stake-amount),
            last-activity: block-height
          })))))))

(define-public (revoke-credential 
  (user principal)
  (credential-id (string-ascii 64)))
  (let ((credential-key {user: user, credential-id: credential-id}))
    (let ((credential (unwrap! (map-get? user-credentials credential-key) err-not-found)))
      (asserts! (or (is-eq tx-sender (get issuer credential)) 
                    (is-eq tx-sender user)
                    (is-eq tx-sender contract-owner)) err-unauthorized)
      (asserts! (not (get revoked credential)) err-credential-revoked)
      (ok (map-set user-credentials credential-key 
        (merge credential {revoked: true}))))))

(define-public (verify-credential 
  (user principal)
  (credential-id (string-ascii 64)))
  (let ((credential-key {user: user, credential-id: credential-id}))
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (let ((credential (unwrap! (map-get? user-credentials credential-key) err-not-found)))
      (asserts! (not (get revoked credential)) err-credential-revoked)
      (asserts! (< block-height (get expires-at credential)) err-expired)
      (map-set user-credentials credential-key 
        (merge credential {verified: true}))
      (let ((profile (unwrap! (map-get? user-profile user) err-not-found)))
        (ok (map-set user-profile user 
          (merge profile {
            verified-credentials: (+ (get verified-credentials profile) u1),
            reputation-score: (min (+ (get reputation-score profile) u5) u1000)
          })))))))

(define-public (endorse-credential 
  (user principal)
  (credential-id (string-ascii 64)))
  (let ((endorser tx-sender)
        (credential-key {user: user, credential-id: credential-id}))
    (let ((endorser-profile (unwrap! (map-get? user-profile endorser) err-not-found))
          (credential (unwrap! (map-get? user-credentials credential-key) err-not-found)))
      (asserts! (>= (get reputation-score endorser-profile) reputation-threshold) err-invalid-endorser)
      (asserts! (not (get revoked credential)) err-credential-revoked)
      (asserts! (< block-height (get expires-at credential)) err-expired)
      (try! (stx-transfer? endorsement-cost endorser (as-contract tx-sender)))
      (map-set user-credentials credential-key 
        (merge credential {endorsement-count: (+ (get endorsement-count credential) u1)}))
      (let ((target-profile (unwrap! (map-get? user-profile user) err-not-found)))
        (ok (map-set user-profile user 
          (merge target-profile {
            reputation-score: (min (+ (get reputation-score target-profile) u3) u1000)
          })))))))

(define-public (batch-verify-credentials 
  (credentials (list 10 {user: principal, credential-id: (string-ascii 64)})))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (ok (fold verify-single-credential credentials (ok u0)))))

(define-private (verify-single-credential 
  (cred-data {user: principal, credential-id: (string-ascii 64)})
  (prev-result (response uint uint)))
  (match prev-result
    ok-value (match (verify-credential (get user cred-data) (get credential-id cred-data))
                success (ok (+ ok-value u1))
                error (err error))
    err-value (err err-value)))

(define-public (increase-stake 
  (user principal)
  (credential-id (string-ascii 64))
  (additional-stake uint))
  (let ((caller tx-sender)
        (credential-key {user: user, credential-id: credential-id}))
    (asserts! (is-eq caller user) err-unauthorized)
    (asserts! (> additional-stake u0) err-invalid-amount)
    (let ((credential (unwrap! (map-get? user-credentials credential-key) err-not-found)))
      (asserts! (not (get revoked credential)) err-credential-revoked)
      (try! (stx-transfer? additional-stake caller (as-contract tx-sender)))
      (map-set user-credentials credential-key 
        (merge credential {stake-amount: (+ (get stake-amount credential) additional-stake)}))
      (let ((profile (unwrap! (map-get? user-profile caller) err-not-found)))
        (ok (map-set user-profile caller 
          (merge profile {total-stake: (+ (get total-stake profile) additional-stake)})))))))

(define-public (withdraw-expired-stake 
  (user principal)
  (credential-id (string-ascii 64)))
  (let ((caller tx-sender)
        (credential-key {user: user, credential-id: credential-id}))
    (asserts! (is-eq caller user) err-unauthorized)
    (let ((credential (unwrap! (map-get? user-credentials credential-key) err-not-found)))
      (asserts! (>= block-height (+ (get expires-at credential) cooling-period)) err-cooling-period)
      (let ((stake-amount (get stake-amount credential)))
        (try! (as-contract (stx-transfer? stake-amount tx-sender caller)))
        (map-delete user-credentials credential-key)
        (let ((profile (unwrap! (map-get? user-profile caller) err-not-found)))
          (ok (map-set user-profile caller 
            (merge profile {
              total-credentials: (- (get total-credentials profile) u1),
              total-stake: (- (get total-stake profile) stake-amount)
            }))))))))

(define-public (slash-stake 
  (user principal)
  (credential-id (string-ascii 64))
  (slash-percentage uint))
  (let ((credential-key {user: user, credential-id: credential-id}))
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (asserts! (<= slash-percentage u100) err-invalid-amount)
    (let ((credential (unwrap! (map-get? user-credentials credential-key) err-not-found)))
      (let ((slash-amount (/ (* (get stake-amount credential) slash-percentage) u100)))
        (map-set user-credentials credential-key 
          (merge credential {
            stake-amount: (- (get stake-amount credential) slash-amount),
            revoked: true
          }))
        (let ((profile (unwrap! (map-get? user-profile user) err-not-found)))
          (ok (map-set user-profile user 
            (merge profile {
              total-stake: (- (get total-stake profile) slash-amount),
              reputation-score: (max (- (get reputation-score profile) u20) u0)
            }))))))))

(define-public (emergency-withdraw)
  (let ((caller tx-sender))
    (asserts! (is-eq caller contract-owner) err-owner-only)
    (let ((contract-balance (stx-get-balance (as-contract tx-sender))))
      (try! (as-contract (stx-transfer? contract-balance tx-sender caller)))
      (ok contract-balance))))

(define-public (create-credential-type 
  (type-id (string-ascii 32))
  (type-name (string-ascii 64))
  (required-stake uint)
  (verification-required bool))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (asserts! (is-none (map-get? credential-types type-id)) err-already-exists)
    (ok (map-set credential-types type-id {
      type-name: type-name,
      required-stake: required-stake,
      verification-required: verification-required,
      created-by: tx-sender,
      active: true
    }))))

(define-public (toggle-credential-type 
  (type-id (string-ascii 32)))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (let ((cred-type (unwrap! (map-get? credential-types type-id) err-not-found)))
      (ok (map-set credential-types type-id 
        (merge cred-type {active: (not (get active cred-type))}))))))

(define-read-only (get-credential 
  (user principal)
  (credential-id (string-ascii 64)))
  (map-get? user-credentials {user: user, credential-id: credential-id}))

(define-read-only (get-user-profile (user principal))
  (map-get? user-profile user))

(define-read-only (get-credential-type (type-id (string-ascii 32)))
  (map-get? credential-types type-id))

(define-read-only (is-credential-valid 
  (user principal)
  (credential-id (string-ascii 64)))
  (match (map-get? user-credentials {user: user, credential-id: credential-id})
    credential (and 
                 (not (get revoked credential))
                 (< block-height (get expires-at credential))
                 (get verified credential))
    false))

(define-read-only (get-user-reputation (user principal))
  (match (map-get? user-profile user)
    profile (get reputation-score profile)
    u0))

(define-read-only (calculate-trust-score 
  (user principal)
  (credential-id (string-ascii 64)))
  (match (get-credential user credential-id)
    credential (let ((base-score (if (get verified credential) u50 u20))
                     (endorsement-score (* (get endorsement-count credential) u5))
                     (stake-score (min (/ (get stake-amount credential) u100000) u20)))
                 (+ base-score endorsement-score stake-score))
    u0))

(define-read-only (get-contract-stats)
  (ok {
    owner: contract-owner,
    min-stake: min-stake-amount,
    reputation-threshold: reputation-threshold,
    endorsement-cost: endorsement-cost,
    cooling-period: cooling-period
  }))

(define-read-only (get-contract-balance)
  (stx-get-balance (as-contract tx-sender)))