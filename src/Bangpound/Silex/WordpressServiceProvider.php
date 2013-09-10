<?php

namespace Bangpound\Silex;

use Silex\ServiceProviderInterface;
use Silex\Application;

class WordpressServiceProvider implements ServiceProviderInterface
{
    /**
     * @param Application $app
     */
    public function register(Application $app)
    {
        // define the authentication listener object
        $app['security.authentication_listener.wordpress._proto'] = $app->protect(function ($providerKey, $options) use ($app) {
            return $app->share(function () use ($app, $providerKey, $options) {
                return new Security\WordpressListener(
                    $app['security'],
                    $app['security.authentication_manager'],
                    $options['document_root'],
                    $app['logger']
                );
            });
        });

        // define the authentication provider object
        $app['security.authentication_provider.wordpress._proto'] = $app->protect(function ($name) use ($app) {
            return $app->share(function () use ($app, $name) {
                return new Security\WordpressAuthenticationProvider();
            });
        });

        $type = 'wordpress';
        $entryPoint = null;

        $app['security.authentication_listener.factory.'.$type] = $app->protect(function($name, $options) use ($type, $app, $entryPoint) {
            if ($entryPoint && !isset($app['security.entry_point.'.$name.'.'.$entryPoint])) {
                $app['security.entry_point.'.$name.'.'.$entryPoint] = $app['security.entry_point.'.$entryPoint.'._proto']($name, $options);
            }

            if (!isset($app['security.authentication_listener.'.$name.'.'.$type])) {
                $app['security.authentication_listener.'.$name.'.'.$type] = $app['security.authentication_listener.'.$type.'._proto']($name, $options);
            }

            $provider = 'wordpress';
            if (!isset($app['security.authentication_provider.'.$name.'.'.$provider])) {
                $app['security.authentication_provider.'.$name.'.'.$provider] = $app['security.authentication_provider.'.$type.'._proto']($name);
            }

            return array(
                'security.authentication_provider.'.$name.'.'.$provider,
                'security.authentication_listener.'.$name.'.'.$type,
                $entryPoint ? 'security.entry_point.'.$name.'.'.$entryPoint : null,
                $type
            );
        });
    }

    /**
     * @see Silex\ServiceProviderInterface::boot
     */
    public function boot(Application $app)
    {
    }
}