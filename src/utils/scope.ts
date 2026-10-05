/**
 * Validates whether a given set of roles or scopes is authorized based on a base set.
 *
 * This function checks if at least one scope in `userScopes` is included
 * within `baseScopes`. It can be used to enforce role-based or permission-based access control.
 *
 * @function scopeValidation
 * @param {Set<string>} baseScopes - The base set of allowed roles or scopes (the reference for validation).
 * @param {Set<string>} [userScopes] - The set of roles or scopes to validate against the base set.
 * @returns {boolean} Returns `OK` if at least one scope in `userScopes` exists within `baseScopes`; otherwise, returns an error message.
 *
 * @example
 * const baseScopes = new Set(['read', 'write', 'admin']);
 * const userScopes = new Set(['read', 'write']);
 *
 * if (scopeValidation(baseScopes, userScopes) === 'OK') {
 *   console.log('Access granted');
 * } else {
 *   console.log('Access denied');
 * }
 */
export const scopeValidation = (
  baseScopes: Set<string>,
  userScopes?: Set<string>,
): 'OK' | string => {
  if (!baseScopes.size) return 'OK'
  if (!userScopes?.size) {
    return `Insufficient permissions. Requires any of [${[...baseScopes].join(', ')}].`
  }

  if (userScopes.has('*')) return 'OK'

  const allScopesSize = userScopes.size + baseScopes.size
  const allUniqueScopes = baseScopes.union(userScopes)

  if (allUniqueScopes.size !== allScopesSize) return 'OK'

  return `Insufficient permissions. Requires any of [${
    [...baseScopes].join(', ')
  }], but received [${[...userScopes].join(', ')}].`
}

/**
 * Lists the required scopes that a held set does not cover, using {@linkcode scopeValidation} one
 * code at a time, so it follows the same rules: a held `*` covers every code, any other held code
 * covers only itself, and no held code but `*` covers a required `*`. There are no prefix
 * wildcards: holding `iam:*` does not cover `iam:read`.
 *
 * Unlike {@linkcode scopeValidation}, which passes when ANY required scope is held, this reports
 * which required scopes are absent, which is what an "ALL of these" check needs (for example,
 * granting only what the grantor holds).
 *
 * @param required - The scopes that must be covered.
 * @param held - The scopes the subject holds. `undefined` is the same as none.
 * @returns The required scopes not covered by `held`, without repeats and in order of first
 *   appearance in `required`. `[]` when everything is covered or `required` is empty. Neither input
 *   is modified.
 *
 * @example
 * ```ts
 * missingScopes(['read', 'write'], ['read']) // ['write']
 * missingScopes(['read', 'write', 'read'], []) // ['read', 'write']
 * missingScopes(['read', 'write'], ['*']) // []
 * missingScopes(['*'], ['read', 'write']) // ['*']
 * missingScopes(['iam:read'], ['iam:*']) // ['iam:read']
 *
 * if (missingScopes(requested, grantor.scope).length) throw new Error('Cannot grant')
 * ```
 */
export const missingScopes = (
  required: Iterable<string>,
  held?: Iterable<string>,
): string[] => {
  const heldScopes = new Set(held ?? [])
  return [...new Set(required)].filter((scope) =>
    scopeValidation(new Set([scope]), heldScopes) !== 'OK'
  )
}
