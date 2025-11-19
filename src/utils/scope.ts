/**
 * Validates whether a given set of roles or scopes is authorized based on a base set.
 *
 * This function checks if all the scopes in the `toValidate` set are included
 * within the `base` set. It can be used to enforce role-based or permission-based access control.
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
