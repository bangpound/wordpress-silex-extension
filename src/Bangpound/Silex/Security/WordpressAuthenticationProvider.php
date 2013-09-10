<?php

namespace Bangpound\Silex\Security;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

class WordpressAuthenticationProvider implements AuthenticationProviderInterface
{
    public function authenticate(TokenInterface $token)
    {
        $user = $token->getUser();

        if ($user) {
            $authenticatedToken = new WordpressUserToken($token->getRoles());
            $authenticatedToken->setUser($user);

            return $authenticatedToken;
        }

        throw new AuthenticationException('Wordpress authentication failed.');
    }

    public function supports(TokenInterface $token)
    {
        return $token instanceof WordpressUserToken;
    }
}
