import pendulum

now = pendulum.now()
# now = pendulum.now("Europe/Paris")   # uncomment to force Paris time

tomorrow = now.add(days=1)
last_week = now.subtract(weeks=1)

print(now)                              # 2025-12-01T10:13:00.123456-05:00
print(now.to_iso8601_string())          # 2025-12-01T10:13:00-05:00
print(now.diff_for_humans())            # "5 seconds ago" or "in 2 hours"


# Pretty printing
print(now.format("MMM D, YYYY hh:mm:ss A"))   # Dec 1, 2025 10:13:00 AM
print(now.to_day_datetime_string())           # Monday, December 1, 2025 10:13 AM