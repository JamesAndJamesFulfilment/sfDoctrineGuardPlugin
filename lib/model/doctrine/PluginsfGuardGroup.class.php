<?php

/**
 * Group model.
 *
 * @package    sfDoctrineGuardPlugin
 * @subpackage model
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id$
 */
abstract class PluginsfGuardGroup extends BasesfGuardGroup
{
    /**
    * Adds the group a permission from its name.
    *
    * @param string $name The permission name
    * @param Doctrine_Connection $con A Doctrine_Connection object
    * @throws sfException
    */
    public function addPermissionByName($name, $con = null)
    {
        $permission = Doctrine_Core::getTable('sfGuardPermission')->findOneByName($name);
        if (!$permission) {
            throw new sfException(sprintf('The permission "%s" does not exist.', $name));
        }

        // Called internally, not by route, act as supervisor approval was granted
        sfGuardGroupPermission::addPermission($this, $permission, true);

        return $this;
    }
}
