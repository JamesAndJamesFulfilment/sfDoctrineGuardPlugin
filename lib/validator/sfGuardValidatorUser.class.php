<?php

/*
 * This file is part of the symfony package.
 * (c) Fabien Potencier <fabien.potencier@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 *
 * @package    symfony
 * @subpackage plugin
 * @author     Fabien Potencier <fabien.potencier@symfony-project.com>
 * @version    SVN: $Id$
 */
class sfGuardValidatorUser extends sfValidatorBase
{
    public function configure($options = [], $messages = [])
    {
        $this->addOption('username_field', 'username');
        $this->addOption('password_field', 'password');
        $this->addOption('throw_global_error', false);

        $this->setMessage('invalid', 'The username and/or password is invalid.');
    }

    protected function doClean($values)
    {
        $username_field = $this->getOption('username_field');
        $password_field = $this->getOption('password_field');
        $username = isset($values[$username_field]) ? $values[$username_field] : '';
        $password = isset($values[$password_field]) ? $values[$password_field] : '';
        if ($username && $users = $this->getTable()->retrieveByUsername($username, false)) {
            $user_count = count($users);
            foreach ($users as $user) {
                if ($user->checkPassword($password)) {
                    if ($user->isActive()) {
                        return array_merge($values, ['user' => $user]);
                    }

                    /*
                     * the password is correct but the user is inactive. if this is the _only_ user
                     * record which matches, attempt to send an email to the user to let them know
                     * their account has been disabled
                     */
                    if ($user_count === 1) {
                        $user->logEvent('retired_user_login_attempt');
                    }
                }
            }
        }

        /*
         * log the failed login attempt
         */
        $ip_address = $this->normaliseRemoteAddress();
        $mysqli     = new mysqli(DATABASE_HOST, DATABASE_USER, DATABASE_PASS, DATABASE_NAME);
        $query      = $mysqli->prepare('INSERT INTO dw_failed_login (username, ip_address, created_at) VALUES (?, INET6_ATON(?), NOW())');

        /*
         * if the prepare() fails for any reason (like the table is missing), then we don't want
         * errors bleeding out
         */
        if ($query) {
            $query->bind_param('ss', $username, $ip_address);
            $mysqli->query('START TRANSACTION;');
            $result = $query->execute();
            $mysqli->query('COMMIT;');
        }

        if ($this->getOption('throw_global_error')) {
            throw new sfValidatorError($this, 'invalid');
        }

        throw new sfValidatorErrorSchema($this, [$username_field => new sfValidatorError($this, 'invalid')]);
    }

    protected function getTable()
    {
        return Doctrine_Core::getTable('sfGuardUser');
    }

    protected function normaliseRemoteAddress()
    {
        $raw = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];

        // convert to binary to prove the address isn't bogus
        $binary = inet_pton($raw);
        if ($binary === false) {
            return null;
        }

        // if the IP is in a mixed format, trim off the leading IPv6 portion
        $prefix = hex2bin('00000000000000000000ffff');
        if (substr($binary, 0, strlen($prefix)) == $prefix) {
            $binary = substr($binary, strlen($prefix));
        }

        // return the canonical value in either IPv4 or IPv6 format
        return inet_ntop($binary);
    }
}
