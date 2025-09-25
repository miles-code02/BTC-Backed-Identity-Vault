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