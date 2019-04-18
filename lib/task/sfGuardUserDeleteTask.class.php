<?php

/*
 * This file is part of the symfony package.
 * (c) Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Delete the given user.
 *
 * @package    symfony
 * @subpackage task
 * @author     Emanuele Panzeri <thepanz@gmail.com>
 */
class sfGuardUserDeleteTask extends sfBaseTask
{
    protected function configure()
    {
        $this->addArguments([
            new sfCommandArgument('username', sfCommandArgument::REQUIRED, 'The user name'),
        ]);

        $this->addOptions([
            new sfCommandOption('application', null, sfCommandOption::PARAMETER_OPTIONAL, 'The application name', null),
            new sfCommandOption('env', null, sfCommandOption::PARAMETER_REQUIRED, 'The environment', 'dev'),
            new sfCommandOption('force', null, sfCommandOption::PARAMETER_NONE, 'Force the deletion of the user'),
        ]);

        $this->namespace = 'guard';
        $this->name = 'user:delete';
        $this->briefDescription = 'Delete the given user';
    }

    protected function execute($arguments = array(), $options = array())
    {
        $databaseManager = new sfDatabaseManager($this->configuration);
        $model = sfConfig::get('app_sf_guard_user_model', 'sfGuardUser');

        /** @var sfGuardUser $user */
        $user = Doctrine_Core::getTable($model)->findOneByUsername($arguments['username']);
        if (!$user)
        {
            throw new sfCommandException(sprintf('User "%s" does not exist.', $arguments['username']));
        }

        if (!$options['force']) {
            $this->logSection('guard', 'User will not be delete, use --force');

            return;
        }


        $user->delete();
    }
}
