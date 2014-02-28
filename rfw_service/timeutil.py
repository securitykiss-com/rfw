import re

def parse_interval(t):
    """Parse time interval t given as string in one of the following formats:
    - <number> representing number of seconds
    - <number>s representing number of seconds
    - <number>h representing number of hours
    - <number>d representing number of days
    return converted number of seconds as integer or None if wrong format
    """
    t = t.strip()
    m = re.match(r"(\d{1,9})([smhd]?)$", t)  # seconds, minutes, hours or days. If none given, seconds assumed.
    if not m:
        return None
    t = int(m.group(1))
    unit = m.group(2)
    multiplier = 1
    if unit == 'm':
        multiplier = 60
    elif unit == 'h':
        multiplier = 3600
    elif unit == 'd':
        multiplier = 86400
    return t * multiplier
