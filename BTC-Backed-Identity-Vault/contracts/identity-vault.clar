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
