<?php

namespace VoterSkeletonBundle\Security\Voter;

use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManagerInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Base class for Voters
 * =====================
 *   Allows to create methods with permission name
 *   that will be used to validate access rights
 */
abstract class AbstractVoter extends Voter
{
    /**
     * @var AccessDecisionManagerInterface $decisionManager
     */
    protected $decisionManager;

    /**
     * @param AccessDecisionManagerInterface $decisionManager
     */
    public function __construct(AccessDecisionManagerInterface $decisionManager)
    {
        $this->decisionManager = $decisionManager;
    }

    /**
     * Optionally limit all input objects to instances
     * of specified class
     *
     * @var string $objectClassName
     */
    protected $objectClassName;

    /**
     * @param string $attribute
     * @param mixed $subject
     *
     * @return bool
     */
    protected function supports($attribute, $subject)
    {
        if (!method_exists($this, 'can' . ucfirst($attribute))) {
            return false;
        }

        $className = get_class($subject);
        $className = str_replace('Proxies\\__CG__\\', '', $className);

        if ($this->objectClassName
            && $className !== $this->objectClassName
            && $subject !== null) {
            return false;
        }

        return true;
    }

    /**
     * @param TokenInterface $token
     * @return bool
     */
    protected function isAdmin(TokenInterface $token)
    {
        // put here your value eg. MySiteRoles::AdminRole
        return $this->hasRole('ROLE_ADMIN', $token);
    }

    /**
     * @param TokenInterface $token
     * @return bool
     */
    protected function isLoggedIn(TokenInterface $token)
    {
        return $token instanceof UsernamePasswordToken;
    }

    /**
     * @param string $role
     * @param TokenInterface $token
     * @return bool
     */
    protected function hasRole($role, TokenInterface $token)
    {
        return $this->decisionManager->decide($token, [ $role ]);
    }

    /**
     * @param string $attribute
     * @param mixed $subject
     * @param TokenInterface $token
     *
     * @return bool
     */
    protected function voteOnAttribute($attribute, $subject, TokenInterface $token)
    {
        $decision = $this->{'can' . ucfirst($attribute)}($subject, $token);

        if ($decision === false && $this->isAdmin($token)) {
            $decision = true;
        }

        return $decision;
    }
}