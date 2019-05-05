<?php

/*
 * This file is part of the symfony package.
 * (c) Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Delete a sfGuard Group.
 *
 * @package    symfony
 * @subpackage task
 * @author     Emanuele Panzeri <thepanz@gmail.com>
 */
class sfGuardGroupDeleteTask extends sfBaseTask
{
  /**
   * @see sfTask
   */
  protected function configure()
  {
    $this->addArguments(array(
      new sfCommandArgument('name', sfCommandArgument::REQUIRED, 'The group name'),
    ));

    $this->addOptions(array(
      new sfCommandOption('application', null, sfCommandOption::PARAMETER_OPTIONAL, 'The application name', null),
      new sfCommandOption('env', null, sfCommandOption::PARAMETER_REQUIRED, 'The environment', 'dev'),
    ));

    $this->namespace = 'guard';
    $this->name = 'group:delete';
    $this->briefDescription = 'Deletes a Group';

    $this->detailedDescription = <<<EOF
The [guard:group:delete|INFO] task deletes a group:

  [./symfony guard:group:delete GroupName|INFO]
EOF;
  }

  /**
   * @see sfTask
   */
  protected function execute($arguments = array(), $options = array())
  {
    $databaseManager = new sfDatabaseManager($this->configuration);

    $table = Doctrine_Core::getTable('sfGuardGroup');
    $entity = $table->findOneBy('name', $arguments['name']);
    if (!$entity) {
      $this->logSection('guard', sprintf('Group "%s" does exists!', $arguments['name']), null, 'ERROR');
      return -1;
    }

    if (!$entity->delete()) {
      $this->logSection('guard', sprintf('Group "%s" was not deleted', $arguments['name']), 'ERROR');
      return -1;
    }

    $this->logSection('guard', sprintf('Group "%s" deleted', $arguments['name']));
  }
}
