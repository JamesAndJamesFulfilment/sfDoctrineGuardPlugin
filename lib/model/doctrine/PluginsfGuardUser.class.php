<?php

/**
 * User model.
 *
 * @package    sfDoctrineGuardPlugin
 * @subpackage model
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id$
 */
abstract class PluginsfGuardUser extends BasesfGuardUser
{
    protected $_groups      = [];
    protected $_permissions = [];

    public function getUsername()
    {
        if (sfContext::getInstance()->getUser()->hasPermission('demo')) {
            $names   = ['itsme', 'examplebuyer', 'ishoponline', 'genie231'];
            $domains = ['hotmail.com', 'gmail.com', 'yahoo.co.uk', 'msn.com', 'aol.com', 'plusnet.net'];

            return "{$names[$this->semiRand(count($names))]}@{$domains[$this->semiRand(count($domains))]}";
        }
        return parent::_get('username');
  }

  /**
   * Returns the string representation of the object.
   *
   * @return string
   */
  public function __toString()
  {
    return (string) $this->getUsername();
  }

    /**
     * Sets the user password.
     *
     * @param string $password
     */
    public function setPassword($password)
    {
        if (!$password && 0 == strlen($password)) {
            return;
        }

        /*
         * if the function password_hash() exists, prefer that to the exclusion of all others.
         * otherwise, defer to the old sha1 logic
         */
        $algorithm = 'password_hash';
        if (is_callable($algorithm)) {
            parent::_set('password', call_user_func_array($algorithm, [$password, PASSWORD_DEFAULT]));
            $this->updatePasswordHashingAlgorithm();
            return;
        }

        if (!$salt = $this->getSalt()) {
            $salt = md5(rand(100000, 999999) . $this->getUsername());
            $this->setSalt($salt);
        }
        $modified = $this->getModified();
        if ((!$algorithm = $this->getAlgorithm()) || (isset($modified['algorithm']) && $modified['algorithm'] == $this->getTable()->getDefaultValueOf('algorithm'))) {
            $algorithm = sfConfig::get('app_sf_guard_plugin_algorithm_callable', 'sha1');
        }
        $algorithmAsStr = is_array($algorithm) ? $algorithm[0] . '::' . $algorithm[1] : $algorithm;
        if (!is_callable($algorithm)) {
            throw new sfException("The algorithm '{$algorithmAsStr}' is not callable.");
        }
        $this->setAlgorithm($algorithmAsStr);

        parent::_set('password', call_user_func_array($algorithm, [$salt . $password]));
    }

  /**
   * Sets the second password.
   *
   * @param string $password
   */
  public function setPasswordBis($password)
  {
  }

    /**
     * Checks if the password has expired
     *
     * @returns bool true if the password is past its expiration date
     */
    public function isExpired()
    {
        return (time() > (int) $this->getDateTimeObject('expires')->format('U'));
    }

    public function isActive()
    {
        return $this->getIsActive();
    }

  /**
   * Returns whether or not the given password is valid.
   *
   * @param string $password
   * @return boolean
   */
  public function checkPassword($password)
  {
    if ($callable = sfConfig::get('app_sf_guard_plugin_check_password_callable'))
    {
      return call_user_func_array($callable, array($this->getUsername(), $password, $this));
    }
    else
    {
      return $this->checkPasswordByGuard($password);
    }
  }

    /**
     * Returns whether or not the given password is valid.
     *
     * @param string $password
     * @return boolean
     * @throws sfException
     */
    public function checkPasswordByGuard($password)
    {
        $algorithm = $this->getAlgorithm();
        if (false !== $pos = strpos($algorithm, '::')) {
            $algorithm = array(substr($algorithm, 0, $pos), substr($algorithm, $pos + 2));
        }
        if (!is_callable($algorithm)) {
            throw new sfException("The algorithm '{$algorithm}' is not callable.");
        }

        $hashed = $this->getPassword();
        if ($algorithm == 'password_hash') {
            $result = password_verify($password, $hashed);

            /*
             * if the password is good and a better hashing algorithm is available (or the cost has
             * changed), rehash the password to automatically increase security
             */
            if (($result === true) && password_needs_rehash($hashed, PASSWORD_DEFAULT)) {
                parent::_set('password', call_user_func_array($algorithm, [$password, PASSWORD_DEFAULT]));
                $this->save();
            }
            return $result;
        }

        $result = $hashed == call_user_func_array($algorithm, [$this->getSalt() . $password]);

        /*
         * if the password is good and the user is using an old password hashing algorithm, rehash
         * the password using a modern algorithm to automatically increase security
         */
        if (($result === true) && ($algorithm !== 'password_hash')) {
            parent::_set('password', password_hash($password, PASSWORD_DEFAULT));
            $this
                ->updatePasswordHashingAlgorithm()
                ->save();
        }

        return $result;
    }

    /*
     * update the password hashing algorithm to the given $algorithm, or default to the
     * currently-recommended password_hash()
     *
     * note: password_hash() internally generates a cryptographically secure salt, which is
     *       encapsulated in the resulting hash string. for this reason, the salt is nulled out
     *       to avoid future confusion about whether the salt was included or not
     */
    protected function updatePasswordHashingAlgorithm($algorithm = 'password_hash')
    {
        if (!is_callable($algorithm)) {
            throw new sfException("The algorithm '{$algorithm}' is not callable.");
        }

        $this->setAlgorithm($algorithm);

        if ($algorithm == 'password_hash') {
            $this->setSalt(null);
        }

        return $this;
    }

    /**
    * Adds the user a new group from its name.
    *
    * @param string $name The group name
    * @param Doctrine_Connection $con A Doctrine_Connection object
    * @throws sfException
    */
    public function addGroupByName($name, $con = null)
    {
        $group = Doctrine_Core::getTable('sfGuardGroup')->findOneByName($name);
        if (!$group) {
            throw new sfException(sprintf('The group "%s" does not exist.', $name));
        }

        // Called internally, not by route, allow supervisor approval for granting the group
        // We also explicitly require the auth check to be completely bypassed in order
        // as we know this is a system call.
        return sfGuardUserGroup::addGroup($this, $group, true, true);
    }

    /**
    * Adds the user a permission from its name.
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
        return sfGuardGroupPermission::addPermission($this, $permission, true);
    }

  /**
   * Checks whether or not the user belongs to the given group.
   *
   * @param string $name The group name
   * @return boolean
   */
  public function hasGroup($name)
  {
    $this->loadGroupsAndPermissions();
    return isset($this->_groups[$name]);
  }

    /**
     * Returns the timestamp of when the user joined $name group
     *
     * @param string $name The group name
     * @return timestamp of date or false
     */
    public function joinedGroupWhen($name)
    {
        if (!$this->hasGroup($name)) {
            return false;
        }
        return strtotime($this->_groups[$name]['group_joined_on']);
    }

  /**
   * Returns all related groups names.
   *
   * @return array
   */
  public function getGroupNames()
  {
    $this->loadGroupsAndPermissions();
    return array_keys($this->_groups);
  }

    /**
     * Returns whether or not the user has the given permission.
     *
     * @return boolean
     */
    public function hasPermission($name)
    {
        $this->loadGroupsAndPermissions();
        return isset($this->_permissions[$name]);
    }

    /**
     * Returns an array of all permission names.
     *
     * @return array
     */
    public function getPermissionNames()
    {
        $this->loadGroupsAndPermissions();
        return array_keys($this->_permissions);
    }

    /**
     * Loads the user's groups and permissions, cached in Redis for an hour
     *
     */
    public function loadGroupsAndPermissions()
    {
        if (empty($this->_permissions)) {
            $name = "PermissionsGroupsByUser-{$this->getId()}";
            $permissions_and_groups = SharedCacheHelper::getValue($name);
            if (!$permissions_and_groups) {
                $query = 'SELECT
                            p.id AS permission_id,
                            p.name AS permission_name,
                            NULL AS group_id,
                            NULL as group_name,
                            NULL as group_joined_on
                          FROM
                            dw_sf_guard_user_permission up
                            JOIN dw_sf_guard_permission p ON (p.id = up.permission_id)
                          WHERE
                            up.user_id = :user_id
                          UNION
                          SELECT
                            p.id AS permission_id,
                            p.name AS permission_name,
                            g.id AS group_id,
                            g.name AS group_name,
                            ug.created_at AS group_joined_on
                          FROM
                            dw_sf_guard_user_group ug
                            JOIN dw_sf_guard_group g ON (g.id = ug.group_id)
                            JOIN dw_sf_guard_group_permission gp ON (gp.group_id = ug.group_id)
                            JOIN dw_sf_guard_permission p ON (p.id = gp.permission_id)
                          WHERE
                            ug.user_id = :user_id';
                $params = ['user_id' => $this->getId()];

                $permissions = Doctrine_Manager::getInstance()->getCurrentConnection()->fetchAssoc($query, $params);
                $permissions_and_groups = [];
                foreach($permissions as $permission) {
                    if (!is_null($permission['group_id'])) {
                        $permissions_and_groups['groups'][$permission['group_name']] = [
                            'id' => $permission['group_id'],
                            'group_joined_on' => $permission['group_joined_on']
                        ];
                    }
                    $permissions_and_groups['permissions'][$permission['permission_name']] = [
                        'id' => $permission['permission_id']
                    ];
                }
                if (!empty($permissions_and_groups['permissions'])) {
                    SharedCacheHelper::setValue($name, json_encode($permissions_and_groups, JSON_PRETTY_PRINT));
                    SharedCacheHelper::setExpiry($name, SharedCacheHelper::ONE_HOUR);
                }
            } else {
                $permissions_and_groups = json_decode($permissions_and_groups, true);
            }
            $this->_groups = isset($permissions_and_groups['groups']) ?
                $permissions_and_groups['groups'] : [];
            $this->_permissions = isset($permissions_and_groups['permissions']) ?
                $permissions_and_groups['permissions'] : [];
        }
    }

    /**
     * Reloads the user's groups and permissions.
     */
    public function reloadGroupsAndPermissions()
    {
        SharedCacheHelper::deleteValue("PermissionsGroupsByUser-{$this->getId()}");
        // we also need to invalidate the cached copy of this user, otherwise any change
        // in permissions/groups won't be noticed when loading that cached user record
        SharedCacheHelper::deleteValue("sfGuardUser-{$this->getId()}");
        $this->_groups      = [];
        $this->_permissions = [];
        $this->loadGroupsAndPermissions();
    }

  /**
   * Sets the password hash.
   *
   * @param string $v
   */
  public function setPasswordHash($v)
  {
    if (!is_null($v) && !is_string($v))
    {
      $v = (string) $v;
    }

    if ($this->password !== $v)
    {
      $this->_set('password', $v);
    }
  }
}
