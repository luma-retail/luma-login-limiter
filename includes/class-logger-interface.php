<?php

declare(strict_types=1);

namespace Luma\LoginLimiter;

interface Logger_Interface {
    /**
     * @param array<string, mixed> $context
     */
    public function log(string $level, string $event, array $context = array()): void;
}
