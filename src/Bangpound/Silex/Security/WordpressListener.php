<?php

namespace Bangpound\Silex\Security;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;

class WordpressListener implements ListenerInterface
{
    protected $securityContext;
    protected $authenticationManager;
    protected $documentRoot;
    protected $logger;

    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, $documentRoot, LoggerInterface $logger = null)
    {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->documentRoot = $documentRoot;
        $this->logger = $logger;
    }

    public function handle(GetResponseEvent $event)
    {
        if (null !== $this->securityContext->getToken()) {
            return;
        }

        $request = $event->getRequest();

        if (!$request->hasSession()) {
            throw new \RuntimeException('This authentication method requires a session.');
        }

        $cookies = array_intersect_key($request->cookies->all(), array_flip(array_filter(array_keys($request->cookies->all()), function ($input) {
            return (strpos($input, 'wordpress_logged_in_') === 0);
        })));

        $logger = $this->logger;

        if (empty($cookies)) {
            return;
        }

        if (null !== $this->logger) {
            $this->logger->debug('Found eligible cookies prefixed with wordpress_logged_in_');
        }

        // Since the closure doesn't keep Wordpress global variables from creeping into Silex's scope, this closure
        // is probably unnecessary.
        $wordpress = function ($cookies) use ($logger) {

            // WordPress creates many global variables. This function attempts to clean up the namespace. Constants
            // cannot be removed.
            $globals_keys = array_keys($GLOBALS);

            // Bootstrap WordPress similarly to xmlrpc.php. Disable cron.
            chdir($this->documentRoot);
            include './wp-load.php';

            // LOGGED_IN_COOKIE is defined in wp-includes/default-constants.php
            if (isset($cookies[LOGGED_IN_COOKIE])) {
                if (null !== $logger) {
                    $logger->debug(sprintf('Wordpress: %s=%s;', LOGGED_IN_COOKIE, $cookies[LOGGED_IN_COOKIE]));
                }
                $user_id = wp_validate_auth_cookie($cookies[LOGGED_IN_COOKIE], 'logged_in');
                if (null !== $logger) {
                    $logger->debug(sprintf('Wordpress: User ID %s', $user_id));
                }
                if ($user_id) {
                    $user = get_userdata($user_id);
                }
            }

            // Remove global variables that were added by WordPress.
            foreach (array_diff(array_keys($GLOBALS), $globals_keys) as $key) {
                unset($GLOBALS[$key]);
            }
            if ($user) {
                if (null !== $logger) {
                    $logger->debug(sprintf('Wordpress: Username %s', $user->data->display_name));
                }
                return $user;
            }
        };

        // Attempt to load a WordPress user based on cookies for this site's domain.
        $user = $wordpress($cookies);
        if (!$user) {
            return;
        }

        // Translate WordPress roles into Symfony Security component roles.
        $roles = array_map(function ($input) {
            return 'ROLE_WORDPRESS_'. strtoupper($input);
        }, $user->roles);
        $roles[] = 'ROLE_USER';

        // Generate token.
        $token = new WordpressUserToken($roles);
        $token->setUser($user->data->display_name);

        try {
            // Authorize token.
            $authToken = $this->authenticationManager->authenticate($token);
            $this->securityContext->setToken($authToken);

            return;
        } catch (AuthenticationException $failed) {
            // To deny the authentication clear the token. This will redirect to the login page.
            // Make sure to only clear your token, not those of other authentication listeners.
            $token = $this->securityContext->getToken();
            if ($token instanceof WordpressUserToken) {
                $this->securityContext->setToken(null);
            }

            // Deny authentication with a '403 Forbidden' HTTP response
            $response = new Response();
            $response->setStatusCode(403);
            $event->setResponse($response);

        }

        // By default deny authorization
        $response = new Response();
        $response->setStatusCode(403);
        $event->setResponse($response);
    }
}
