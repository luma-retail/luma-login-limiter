<?php

declare(strict_types=1);

namespace Luma\LoginLimiter;

final class Xmlrpc_Manager {
    public function __construct(
        private readonly Gateway_Context $context,
        private readonly Ip_Resolver $ip_resolver,
        private readonly Logger_Interface $logger
    ) {
    }

    public function register(): void {
        add_filter('xmlrpc_methods', array($this, 'filter_methods'));
    }

    /**
     * @param array<string, callable> $methods
     * @return array<string, callable>
     */
    public function filter_methods(array $methods): array {
        $methods['system.multicall'] = array($this, 'deny_system_multicall');
        $methods['pingback.ping'] = array($this, 'deny_pingback');
        $methods['pingback.extensions.getPingbacks'] = array($this, 'deny_pingback_extensions');

        return $methods;
    }

    /**
     * @param array<int, mixed> $args
     */
    public function deny_system_multicall(array $args): \IXR_Error {
        return $this->deny_method('system.multicall');
    }

    /**
     * @param array<int, mixed> $args
     */
    public function deny_pingback(array $args): \IXR_Error {
        return $this->deny_method('pingback.ping');
    }

    /**
     * @param array<int, mixed> $args
     */
    public function deny_pingback_extensions(array $args): \IXR_Error {
        return $this->deny_method('pingback.extensions.getPingbacks');
    }

    private function deny_method(string $method): \IXR_Error {
        $this->context->set_xmlrpc_method($method);

        $this->logger->log(
            'warning',
            'xmlrpc_method_denied',
            array(
                'component'   => 'xmlrpc',
                'gateway'     => 'xmlrpc',
                'username'    => '',
                'ip'          => $this->ip_resolver->resolve(),
                'outcome'     => 'denied',
                'reason_code' => 'xmlrpc_method_disabled',
                'method'      => $method,
            )
        );

        return new \IXR_Error(403, __('This XML-RPC method is disabled by Luma Login Limiter.', 'luma-login-limiter'));
    }
}
