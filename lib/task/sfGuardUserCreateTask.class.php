<?php

/*
 * This file is part of the symfony package.
 * (c) Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Create a new user.
 *
 * @package    symfony
 * @subpackage task
 * @author     Emanuele Panzeri <thepanz@gmail.com>
 */
class sfGuardUserCreateTask extends sfBaseTask
{
  /**
   * @see sfTask
   */
  protected function configure()
  {
    $this->addArguments(array(
      new sfCommandArgument('email_address', sfCommandArgument::REQUIRED, 'The email address'),
      new sfCommandArgument('username', sfCommandArgument::REQUIRED, 'The username'),
      new sfCommandArgument('password', sfCommandArgument::REQUIRED, 'The password'),
      new sfCommandArgument('first_name', sfCommandArgument::OPTIONAL, 'The first name'),
      new sfCommandArgument('last_name', sfCommandArgument::OPTIONAL, 'The last name'),
    ));

    $this->addOptions(array(
      new sfCommandOption('is-super-admin', null, sfCommandOption::PARAMETER_NONE, 'Whether the user is a super admin', null),
      new sfCommandOption('application', null, sfCommandOption::PARAMETER_OPTIONAL, 'The application name', null),
      new sfCommandOption('env', null, sfCommandOption::PARAMETER_REQUIRED, 'The environment', 'dev'),
    ));

    $this->namespace = 'guard';
    $this->name = 'user:create';
    $this->briefDescription = 'Creates a user';

    $this->detailedDescription = <<<EOF
The [guard:user:create|INFO] task creates a user:

  [./symfony guard:user:create mail@example.com fabien password Fabien POTENCIER|INFO]
EOF;
  }

  /**
   * @see sfTask
   */
  protected function execute($arguments = array(), $options = array())
  {
    $databaseManager = new sfDatabaseManager($this->configuration);

    $model = sfConfig::get('app_sf_guard_user_model', 'sfGuardUser');

    $user = new $model();
    $user->setEmailAddress($arguments['email_address']);
    $user->setUsername($arguments['username']);
    $user->setPassword($arguments['password']);
    $user->setFirstName($arguments['first_name']);
    $user->setLastName($arguments['last_name']);
    $user->setIsActive(true);
    $user->setIsSuperAdmin($options['is-super-admin']);
    $user->save();

    $this->logSection('guard', sprintf('Create user "%s"', $arguments['username']));
  }
}
