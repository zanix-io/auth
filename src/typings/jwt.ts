/**
 * Represents the available JWT signing algorithms.
 * These algorithms are used for signing the JWT.
 * They can either be based on RSA or HMAC (HS) algorithms.
 */
export type JWTAlgorithm =
  | 'RS256' // RSA with SHA-256
  | 'RS384' // RSA with SHA-384
  | 'RS512' // RSA with SHA-512
  | 'HS256' // HMAC with SHA-256
  | 'HS384' // HMAC with SHA-384
  | 'HS512' // HMAC with SHA-512

/**
 * Represents the JWT header, which contains metadata about the token,
 * such as the signing algorithm, type of token, and an optional key identifier (kid).
 * It may also include a custom "encrypt" property indicating whether the payload is encrypted.
 *
 * @property {JWTAlgorithm} alg - The algorithm used to sign the JWT.
 *                                 Possible values include `RS256`, `HS256`, etc.
 * @property {'JWT'} typ - The type of the token. Typically, this is always "JWT".
 * @property {string} [kid] - The key ID (optional). A string that identifies the key used to sign the JWT.
 *                            Useful for multi-key systems to know which key to use for verification.
 */
export type JWTHeader = {
  /** The algorithm used for signing (e.g., RS256, HS256, etc.) */
  alg: JWTAlgorithm
  /** The type of the token (always "JWT"). */
  typ: 'JWT'
  /** Optional key ID (if using multiple keys). */
  kid?: string
}

/**
 * Represents the JWT payload, which is the actual content of the token.
 * It can include claims like the issuer (`iss`), subject (`sub`), audience (`aud`), and expiration (`exp`).
 * The payload can either be a plain object (in the case of unencrypted tokens) or a string (if the payload is encrypted).
 *
 * @property {string} [jti] - The the token UID (optional).
 * @property {string} [iss] - The issuer of the token (optional).
 *                            Identifies who created and signed the JWT.
 * @property {string} [sub] - The subject of the token (optional).
 *                            Typically, it represents the user or entity the token is about.
 * @property {string | string[]} [aud] - The audience of the token (optional).
 *                                      Identifies the recipients that the token is intended for.
 *                                      It can be a string or an array of strings.
 * @property {number} [exp] - The expiration time of the token, in seconds since the Unix epoch (optional).
 *                            After this time, the token will no longer be valid.
 * @property {boolean} [secureData] - Optional property to store secure data.
 *                                    This data is automatically encrypted when generated.
 *                                    During verification, it is automatically decrypted.
 *                                    No manual encryption or decryption is required by the user.
 *                                    **Note:** You need to provide an encryption secret key when using the `RSA` algorithm.
 */
export type JWTPayload = {
  // deno-lint-ignore no-explicit-any
  [key: string]: any
  /** JWT unique identifier. */
  jti: string
  /** Issuer claim (identifies who created and signed the JWT). */
  iss: string | undefined
  /** Subject claim (the user or entity ID). */
  sub?: string | undefined
  /** Audience claim (permissions, scope, roles). */
  aud?: string | string[] | undefined
  /** Expiration time in Unix timestamp. */
  exp?: number | undefined
  /** The secure data (automatically encrypted when generated)*/
  secureData?: string
}

/**
 * Represents a complete JWT.
 * A JWT consists of a header, payload, and signature. The header contains metadata about the JWT,
 * the payload contains the claims, and the signature ensures the integrity and authenticity of the token.
 *
 * @property {JWTHeader} header - The JWT header, containing information about the algorithm and type.
 * @property {JWTPayload | string} payload - The JWT payload, which may either be a plain object or a string (if it is encrypted).
 * @property {string} signature - The cryptographic signature, used to verify the authenticity and integrity of the token.
 */
export type JWT = {
  header: JWTHeader
  payload: JWTPayload
  signature: string
}

export type JWTOptions = {
  /**
   * The signing algorithm (default hash is SHA-256 and default algorithm is HMAC).
   */
  algorithm?: JWTAlgorithm
  /**
   * The key used to encrypt or protect the payload's sensitive data.
   * Required on JWT RSA mode.
   */
  encryptionKey?: string
}

/** JWT Verify settins */
export type JWTVerifyOptions = JWTOptions & Pick<Partial<JWTPayload>, 'iss' | 'sub' | 'aud'>
