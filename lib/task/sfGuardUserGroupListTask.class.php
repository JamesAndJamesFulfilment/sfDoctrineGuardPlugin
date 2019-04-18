<?php

/*
 * This file is part of the symfony package.
 * (c) Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * List the group associated to a user.
 *
 * @package    symfony
 * @subpackage task
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id$
 */
class sfGuardUserGroupListTask extends sfBaseTask
{
  protected function configure()
  {
    $this->addArguments(array(
      new sfCommandArgument('username', sfCommandArgument::REQUIRED, 'The user name'),
    ));

    $this->addOptions(array(
      new sfCommandOption('application', null, sfCommandOption::PARAMETER_OPTIONAL, 'The application name', null),
      new sfCommandOption('env', null, sfCommandOption::PARAMETER_REQUIRED, 'The environment', 'dev'),
    ));

    $this->name = 'user:group-list';
    $this->namespace = 'guard';
    $this->briefDescription = 'List the Groups associated to a user';
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

    $this->logSection('guard', sprintf('Listing groups associated to user %s', $arguments['username']));
    foreach ($user->getGroupNames() as $groupName) {
        $this->logSection('guard', sprintf(' - %s', $groupName));
    }
  }
}
