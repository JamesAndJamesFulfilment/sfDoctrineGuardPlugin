<?php

/*
 * This file is part of the symfony package.
 * (c) Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 * Update a sfGuard Group.
 *
 * @package    symfony
 * @subpackage task
 * @author     Emanuele Panzeri <thepanz@gmail.com>
 */
class sfGuardGroupUpdateTask extends sfBaseTask
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
            new sfCommandOption('description', null, sfCommandOption::PARAMETER_REQUIRED, 'The new group description', null),
            new sfCommandOption('name', null, sfCommandOption::PARAMETER_REQUIRED, 'The new group name', null),
            new sfCommandOption('application', null, sfCommandOption::PARAMETER_OPTIONAL, 'The application name', null),
            new sfCommandOption('env', null, sfCommandOption::PARAMETER_REQUIRED, 'The environment', 'dev'),
        ));

        $this->namespace = 'guard';
        $this->name = 'group:update';
        $this->briefDescription = 'Updates a Group';

        $this->detailedDescription = <<<EOF
The [guard:group:update|INFO] task update a group:

  [./symfony guard:group:update GroupName --description="This is a nice Group description"|INFO]
EOF;
    }

    /**
     * @see sfTask
     */
    protected function execute($arguments = array(), $options = array())
    {
        $databaseManager = new sfDatabaseManager($this->configuration);

        $table = Doctrine_Core::getTable('sfGuardGroup');
        /** @var sfGuardGroup $entity */
        $entity = $table->findOneBy('name', $arguments['name']);
        if (!$entity) {
            $this->logSection('guard', sprintf('Group "%s" does exists!', $arguments['name']), null, 'ERROR');
            return -1;
        }

        if (null === $options['description'] && !$options['name']) {
            $this->logSection('guard', 'You must define at least a new name or description!', null, 'ERROR');
            return -1;
        }

        if (null !== $options['description']) {
            $entity->setDescription($arguments['description']);
        }
        if ($options['name']) {
            $entity->setName($options['name']);
        }

        $entity->save();
        $this->logSection('guard', sprintf('Group "%s" updated', $arguments['name']));
    }
}
