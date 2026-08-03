# 🔒 IP Allowlisting

Protect controllers and routes by restricting access to a configured set of client IP addresses or
CIDR ranges.

This feature is intended as an additional security layer for sensitive endpoints such as
administration panels, internal APIs, webhooks, or infrastructure-only services.

> **Important:** IP allowlisting should complement authentication and authorization, not replace
> them. It is recommended to combine it with `@AuthTokenValidation` for privileged endpoints.

---

## 📋 Table of Contents

1. [Basic Usage](#-basic-usage)
2. [Using the Environment Variable](#-using-the-environment-variable)
3. [CIDR Ranges](#-cidr-ranges)
4. [Trusted Proxy Headers](#-trusted-proxy-headers)
5. [Security Considerations](#-security-considerations)
6. [API Reference](#-api-reference)
7. [Recommended Usage](#-recommended-usage)
8. [See also](#see-also)

---

## 🚀 Basic Usage

Apply the decorator to a controller:

```ts
import { AuthTokenValidation, IpAllowlistGuard } from 'jsr:@zanix/auth'

@Controller()
@AuthTokenValidation({ permissions: ['admin'] })
@IpAllowlistGuard({
  allow: [
    '10.0.0.0/8',
    '192.168.1.25',
  ],
  trustProxyHeader: true,
})
export class AdminController {}
```

Requests originating from an address outside the configured allowlist receive an HTTP **403
Forbidden** response.

---

## 🌎 Using the Environment Variable

Instead of configuring the allowlist directly in code, it can be supplied through the
`ADMIN_IP_ALLOWLIST` environment variable.

```env
ADMIN_IP_ALLOWLIST=10.0.0.0/8,192.168.1.25,203.0.113.15
```

Then simply enable the guard:

```ts
@IpAllowlistGuard({
  trustProxyHeader: true,
})
```

When `allow` is omitted, the guard automatically falls back to the environment variable.

If neither `allow` nor `ADMIN_IP_ALLOWLIST` is configured, the guard becomes a pass-through and does
not restrict requests.

---

## 🌐 CIDR Ranges

Both exact IP addresses and IPv4 CIDR ranges are supported.

```ts
allow: ;
;[
  '10.0.0.5',
  '192.168.1.0/24',
  '172.16.0.0/12',
]
```

Examples:

| Entry            | Matches                |
| ---------------- | ---------------------- |
| `203.0.113.5`    | Only `203.0.113.5`     |
| `192.168.1.0/24` | `192.168.1.x`          |
| `10.0.0.0/8`     | Any `10.x.x.x` address |

---

## 🔀 Trusted Proxy Headers

Client IPs are resolved from trusted proxy headers in the following order:

1. `x-forwarded-for`
2. `cf-connecting-ip`
3. `x-real-ip`

By default, all three headers are considered.

You may restrict which headers are trusted:

```ts
@IpAllowlistGuard({
  allow: ['203.0.113.5'],
  trustProxyHeader: true,
  trustedHeaders: ['cf-connecting-ip'],
})
```

This is useful when your infrastructure guarantees a specific header.

---

## 🛡️ Security Considerations

HTTP proxy headers are client-controlled unless your infrastructure overwrites them.

For this reason, **an allowlist cannot be enabled unless `trustProxyHeader` is explicitly set to
`true`**.

```ts
@IpAllowlistGuard({
  allow: ['10.0.0.0/8'],
  trustProxyHeader: true,
})
```

Attempting to configure an allowlist without acknowledging this requirement throws an
`InternalError` during application startup.

Only enable `trustProxyHeader` when requests pass through a trusted reverse proxy such as:

- Cloudflare
- NGINX
- Traefik
- HAProxy
- Kubernetes Ingress
- AWS ALB / ELB

These proxies should be configured to overwrite client IP headers before forwarding requests to your
application.

---

## 📚 API Reference

### `IpAllowlistGuard(options?)`

Class decorator that applies IP allowlisting to a controller.

```ts
@IpAllowlistGuard(options)
```

---

### `ipAllowlistGuard(options?)`

Middleware guard that can be registered manually.

```ts
ipAllowlistGuard(options)
```

---

### `IpAllowlistOptions`

```ts
interface IpAllowlistOptions {
  allow?: string[]
  trustProxyHeader?: boolean
  trustedHeaders?: string[]
}
```

| Option             | Description                                                             |
| ------------------ | ----------------------------------------------------------------------- |
| `allow`            | Exact IP addresses or CIDR ranges allowed to access the resource.       |
| `trustProxyHeader` | Must be `true` whenever an allowlist is configured.                     |
| `trustedHeaders`   | Restricts which proxy headers are trusted when resolving the client IP. |

---

## 💡 Recommended Usage

For administrative or internal endpoints, combine authentication, authorization, and IP
allowlisting:

```ts
@Controller()
@AuthTokenValidation({ permissions: ['admin'] })
@IpAllowlistGuard({
  allow: ['10.0.0.0/8'],
  trustProxyHeader: true,
})
export class AdminController {}
```

This provides:

- Authentication via JWT.
- Authorization through permissions.
- Network-level access restriction using an IP allowlist.

---

## See also

- [README](../README.md) — installation, core registration, and basic usage.
- [Service-Credential Exchange Guide](./service-credential.md) — a complementary layer for
  service-to-service calls, worth combining with an allowlist on the receiving endpoint.
- [Changelog](../CHANGELOG.md) — version history.
