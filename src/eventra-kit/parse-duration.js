
/**
 * adds a duration parser.
 */
export function parseDuration(text) {
  const matches = String(text).matchAll(/(\d+(?:\.\d+)?)\s*(s|m|h|d)/gi);
  let total = 0;
  let found = false;
  for (const m of matches) {
    found = true;
    const value = parseFloat(m[1]);
    const unit = m[2].toLowerCase();
    total += value * (unit === 'd' ? 86400 : unit === 'h' ? 3600 : unit === 'm' ? 60 : 1);
  }
  return found ? total : 0;
}

