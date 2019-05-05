<?php

/*
 * This file is part of the symfony package.
 * (c) Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * List the available Permissions.
 *
 * @package    symfony
 * @subpackage task
 * @author     Emanuele Panzeri <thepanz@gmail.com>
 */
class sfGuardPermissionListTask extends sfBaseTask
{
  protected function configure()
  {
    $this->addArguments(array());

    $this->addOptions(array(
      new sfCommandOption('with-groups', null, sfCommandOption::PARAMETER_NONE, 'Join with Groups'),
      new sfCommandOption('with-users', null, sfCommandOption::PARAMETER_NONE, 'Join with Users'),
      new sfCommandOption('application', null, sfCommandOption::PARAMETER_OPTIONAL, 'The application name', null),
      new sfCommandOption('env', null, sfCommandOption::PARAMETER_REQUIRED, 'The environment', 'dev'),
    ));

    $this->namespace = 'guard';
    $this->name = 'permission:list';
    $this->briefDescription = 'List Permissions';
  }

  protected function execute($arguments = array(), $options = array())
  {
    $databaseManager = new sfDatabaseManager($this->configuration);

    $permTable = Doctrine_Core::getTable('sfGuardPermission');

    $perms = $permTable->findAll();

    $this->logSection('guard', sprintf('Found %d Permissions', $perms->count()));

      /** @var sfGuardPermission $perm */
    foreach($perms as $perm) {
        $this->logSection('guard', sprintf(' - %s', $perm->getName()));
        if ($options['with-groups']) {
            foreach ($perm->getSfGuardGroupPermission() as $groupPermission) {
                $this->logSection('guard', sprintf('   - Group: %s', $groupPermission->getGroup()->getName()));
            }
        }
    }
      if ($options['with-users']) {
          foreach ($perm->getUsers() as $user) {
              $this->logSection('guard', sprintf('   - User: %s', $user->getName()));
          }
      }

  }
}
