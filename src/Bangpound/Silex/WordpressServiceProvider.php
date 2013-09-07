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
    }

    /**
     * @see Silex\ServiceProviderInterface::boot
     */
    public function boot(Application $app)
    {
    }
}