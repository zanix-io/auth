export const RATE_LIMIT = `
  local key = KEYS[1]
  local failedAttemptsKey = KEYS[2]
  local maxRequests = tonumber(ARGV[1])
  local windowSeconds = tonumber(ARGV[2])
  local maxFaildedAttempts = tonumber(ARGV[3])
  local now = tonumber(ARGV[4])

  local dataJson = redis.call("GET", key)
  local data
  if dataJson then
    data = cjson.decode(dataJson)
  else
    data = { count = 0, createdAt = now }
    redis.call("SETEX", key, windowSeconds, cjson.encode(data))
  end

  local count = data.count
  local createdAt = data.createdAt

  if (count) >= maxRequests then
    local failedAttempts = tonumber(redis.call("GET", failedAttemptsKey) or 0)
    if failedAttempts >= maxFaildedAttempts then
      redis.call("DEL", failedAttemptsKey)
    end
    return cjson.encode({ count = count, createdAt = createdAt, failedAttempts = failedAttempts, canContinue = false })
  end

  if count == 1 and maxFaildedAttempts and maxFaildedAttempts > 0 then
    local failedAttempts = tonumber(redis.call("GET", failedAttemptsKey) or 0)
    redis.call("SETEX", failedAttemptsKey, windowSeconds * maxFaildedAttempts * 2, failedAttempts + 1)
  end

  data.count = count + 1
  redis.call("SET", key, cjson.encode(data), "KEEPTTL")

  return cjson.encode({ count = data.count, createdAt = createdAt, failedAttempts = 0, canContinue = true })
  `
