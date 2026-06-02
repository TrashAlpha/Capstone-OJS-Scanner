<?php

namespace App\Support;

class CronBuilder
{
    /**
     * Bangun ekspresi cron dari preset ramah-pengguna.
     *
     * @param  string       $frequency   hourly|daily|weekly|monthly
     * @param  string|null  $time        "HH:MM" (untuk daily/weekly/monthly)
     * @param  int|null     $weekday     0-6 (Minggu-Sabtu) untuk weekly
     * @param  int|null     $dayOfMonth  1-28 untuk monthly
     */
    public static function build(string $frequency, ?string $time = null, ?int $weekday = null, ?int $dayOfMonth = null): string
    {
        [$hour, $minute] = self::parseTime($time);

        return match ($frequency) {
            'hourly'  => sprintf('%d * * * *', $minute),
            'weekly'  => sprintf('%d %d * * %d', $minute, $hour, self::clamp($weekday ?? 1, 0, 6)),
            'monthly' => sprintf('%d %d %d * *', $minute, $hour, self::clamp($dayOfMonth ?? 1, 1, 28)),
            default   => sprintf('%d %d * * *', $minute, $hour), // daily
        };
    }

    /**
     * @return array{0:int,1:int} [hour, minute]
     */
    private static function parseTime(?string $time): array
    {
        if ($time && preg_match('/^(\d{1,2}):(\d{2})$/', $time, $m)) {
            return [self::clamp((int) $m[1], 0, 23), self::clamp((int) $m[2], 0, 59)];
        }

        return [2, 0]; // default 02:00
    }

    private static function clamp(int $value, int $min, int $max): int
    {
        return max($min, min($max, $value));
    }
}
