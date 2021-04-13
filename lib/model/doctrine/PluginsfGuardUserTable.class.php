<?php

/**
 * User table.
 *
 * @package    sfDoctrineGuardPlugin
 * @subpackage model
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id$
 */
abstract class PluginsfGuardUserTable extends Doctrine_Table
{
    /**
     * Retrieves a sfGuardUser object by username and is_active flag.
     *
     * @param  string  $username The username
     * @param  boolean $only_include_active Whether to include only active users (true) or all users (false)
     *
     * @return sfGuardUser
     */
    public function retrieveByUsername($username, $only_include_active = true)
    {
        $query = Doctrine_Core::getTable('sfGuardUser')
            ->createQuery('u')
            ->where('u.username = ?', $username);

        if ($only_include_active) {
            $query->addWhere('u.is_active = 1');
        }

        return $query->execute();
    }
}
