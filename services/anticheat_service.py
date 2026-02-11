"""
Anti-Cheat Service - Flag validation and cheat detection
"""
import logging
from datetime import datetime
from flask import request
from CTFd.models import db
from ..models.flag import ContainerFlag, ContainerFlagAttempt
from ..models.audit import ContainerAuditLog
from .flag_service import FlagService

logger = logging.getLogger(__name__)


class AntiCheatService:
    """
    Service to validate flags and detect cheating
    """
    
    def __init__(self, flag_service: FlagService, notification_service=None):
        self.flag_service = flag_service
        self.notification_service = notification_service
    
    def validate_flag(
        self,
        challenge_id: int,
        account_id: int,
        user_id: int,
        submitted_flag: str
    ) -> tuple:
        """
        Validate submitted flag
        
        Args:
            challenge_id: Challenge ID
            account_id: Team/User ID
            user_id: Actual user submitting
            submitted_flag: Submitted flag text
        
        Returns:
            (is_correct: bool, message: str, is_cheating: bool)
        """
        from ..models.challenge import ContainerChallenge
        challenge = ContainerChallenge.query.get(challenge_id)
        if not challenge:
            return (False, "Challenge not found", False)
        
        flag_hash = FlagService.hash_flag(submitted_flag)
        ip_address = request.remote_addr if request else None
        user_agent = request.headers.get('User-Agent') if request else None
        
        attempt = ContainerFlagAttempt(
            challenge_id=challenge_id,
            account_id=account_id,
            user_id=user_id,
            submitted_flag_hash=flag_hash,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        if challenge.flag_mode == 'static':
            static_flag = f"{challenge.flag_prefix}{challenge.flag_suffix}"
            
            if submitted_flag == static_flag:
                # Correct static flag
                attempt.is_correct = True
                attempt.is_cheating = False
                
                audit_log = ContainerAuditLog(
                    event_type='flag_submitted_correct',
                    challenge_id=challenge_id,
                    account_id=account_id,
                    user_id=user_id,
                    details={'flag_mode': 'static', 'ip_address': ip_address},
                    severity='info',
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                
                db.session.add(attempt)
                db.session.add(audit_log)
                db.session.commit()
                
                logger.info(f"Account {account_id} correctly submitted static flag for challenge {challenge_id}")
                return (True, "Correct", False)
            else:
                attempt.is_correct = False
                attempt.is_cheating = False
                db.session.add(attempt)
                db.session.commit()
                
                logger.info(f"Account {account_id} submitted incorrect static flag for challenge {challenge_id}")
                return (False, "Incorrect", False)
        
        flag_record = ContainerFlag.query.filter_by(flag_hash=flag_hash).first()
        
        if not flag_record:
            attempt.is_correct = False
            attempt.is_cheating = False
            db.session.add(attempt)
            db.session.commit()
            
            logger.info(f"Account {account_id} submitted non-existent flag for challenge {challenge_id}")
            return (False, "Incorrect", False)
        
        if flag_record.flag_status == 'invalidated':
            attempt.is_correct = False
            attempt.is_cheating = False
            db.session.add(attempt)
            db.session.commit()
            
            logger.info(f"Account {account_id} submitted invalidated flag for challenge {challenge_id}")
            return (False, "This flag has expired", False)
        
        if flag_record.account_id != account_id:
            attempt.is_correct = False
            attempt.is_cheating = True
            attempt.flag_owner_account_id = flag_record.account_id
            
            from CTFd.models import Teams, Users, Challenges
            from CTFd.utils import get_config
            from CTFd.schemas.notifications import NotificationSchema
            from flask import current_app
            
            mode = get_config('user_mode')
            is_team_mode = (mode == 'teams')
            
            from ..models.config import ContainerConfig
            fame_or_shame = ContainerConfig.get('fame_or_shame', '0')
            
            if is_team_mode:
                cheater_team = Teams.query.get(account_id)
                owner_team = Teams.query.get(flag_record.account_id)
                
                if cheater_team:
                    cheater_team.banned = True
                    cheater_members = Users.query.filter_by(team_id=account_id).all()
                    for member in cheater_members:
                        member.banned = True
                    logger.critical(f"BANNED team {account_id} ({cheater_team.name}) and {len(cheater_members)} members for flag reuse")
                
                if owner_team:
                    owner_team.banned = True
                    owner_members = Users.query.filter_by(team_id=flag_record.account_id).all()
                    for member in owner_members:
                        member.banned = True
                    logger.critical(f"BANNED team {flag_record.account_id} ({owner_team.name}) and {len(owner_members)} members for possible flag sharing")
                
                if fame_or_shame == '1' and cheater_team and owner_team:
                    challenge_obj = Challenges.query.filter_by(id=challenge_id).first()
                    if challenge_obj:
                        notification_title = "Cheating Detected!"
                        notification_content = (
                            f"Flag swapping detected between {cheater_team.name} and {owner_team.name} "
                            f"on challenge '{challenge_obj.name}'. Both teams have been banned."
                        )
                        
                        notification_data = {
                            "title": notification_title,
                            "content": notification_content,
                            "sound": True,
                            "type": "toast"
                        }
                        
                        schema = NotificationSchema()
                        result = schema.load(notification_data)
                        if not result.errors:
                            db.session.add(result.data)
                            db.session.commit()
                            
                            response = schema.dump(result.data)
                            response.data["type"] = "toast"
                            response.data["sound"] = True
                            current_app.events_manager.publish(data=response.data, type="notification")
            else:
                cheater_user = Users.query.get(account_id)
                owner_user = Users.query.get(flag_record.account_id)
                
                if cheater_user:
                    cheater_user.banned = True
                    logger.critical(f"BANNED user {account_id} ({cheater_user.name}) for flag reuse")
                
                if owner_user:
                    owner_user.banned = True
                    logger.critical(f"BANNED user {flag_record.account_id} ({owner_user.name}) for possible flag sharing")
                
                if fame_or_shame == '1' and cheater_user and owner_user:
                    challenge_obj = Challenges.query.filter_by(id=challenge_id).first()
                    if challenge_obj:
                        notification_title = "Cheating Detected!"
                        notification_content = (
                            f"Flag reuse detected between {owner_user.name} and {cheater_user.name} "
                            f"on challenge '{challenge_obj.name}'. Both users have been banned."
                        )
                        
                        notification_data = {
                            "title": notification_title,
                            "content": notification_content,
                            "sound": True,
                            "type": "toast"
                        }
                        
                        schema = NotificationSchema()
                        result = schema.load(notification_data)
                        if not result.errors:
                            db.session.add(result.data)
                            db.session.commit()
                            
                            response = schema.dump(result.data)
                            response.data["type"] = "toast"
                            response.data["sound"] = True
                            current_app.events_manager.publish(data=response.data, type="notification")
            
            audit_log = ContainerAuditLog(
                event_type='flag_reuse_detected',
                challenge_id=challenge_id,
                account_id=account_id,
                user_id=user_id,
                details={
                    'submitted_flag_hash': flag_hash,
                    'actual_owner_account_id': flag_record.account_id,
                    'flag_status': flag_record.flag_status,
                    'ip_address': ip_address,
                    'action_taken': 'both_accounts_banned'
                },
                severity='critical',
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            db.session.add(attempt)
            db.session.add(audit_log)
            db.session.commit()
            
            logger.warning(
                f"CHEAT DETECTED: Account {account_id} submitted flag belonging to {flag_record.account_id} "
                f"for challenge {challenge_id} - BOTH ACCOUNTS BANNED"
            )

            if self.notification_service:
                self.notification_service.notify_cheat(
                    user=cheater_user if not is_team_mode else None,
                    challenge=challenge,
                    flag=submitted_flag,
                    owner=owner_user if not is_team_mode else None
                )
            
            return (False, "Incorrect", True)
        
        if flag_record.account_id == account_id:
            # 7.1. Already submitted (duplicate)
            if flag_record.flag_status == 'submitted_correct':
                attempt.is_correct = True
                attempt.is_cheating = False
                db.session.add(attempt)
                db.session.commit()
                
                logger.info(f"Account {account_id} re-submitted already solved challenge {challenge_id}")
                return (True, "Already solved", False)
            
            # 7.2. First correct submission
            flag_record.mark_as_submitted(user_id, ip_address)
            
            # Note: Do NOT update instance status here
            # The ContainerService.stop_instance() will handle it when called after validation
            # This allows __init__.py to find instance with status='running' to stop it
            
            attempt.is_correct = True
            attempt.is_cheating = False
            
            # Audit log
            audit_log = ContainerAuditLog(
                event_type='flag_submitted_correct',
                instance_id=flag_record.instance_id,
                challenge_id=challenge_id,
                account_id=account_id,
                user_id=user_id,
                details={'ip_address': ip_address},
                severity='info',
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            db.session.add(attempt)
            db.session.add(audit_log)
            db.session.commit()
            
            logger.info(f"Account {account_id} correctly solved challenge {challenge_id}")
            
            return (True, "Correct!", False)
        
        # 8. Fallback
        return (False, "Unexpected error", False)
    
    def get_cheat_attempts(self, limit=100):
        """
        Get recent cheat attempts
        
        Returns:
            List of ContainerFlagAttempt records where is_cheating=True
        """
        return ContainerFlagAttempt.query.filter_by(
            is_cheating=True
        ).order_by(
            ContainerFlagAttempt.timestamp.desc()
        ).limit(limit).all()
    
    def get_account_attempts(self, account_id, challenge_id=None):
        """
        Get flag attempts for an account
        
        Args:
            account_id: Account ID
            challenge_id: Optional challenge filter
        
        Returns:
            List of attempts
        """
        query = ContainerFlagAttempt.query.filter_by(account_id=account_id)
        
        if challenge_id:
            query = query.filter_by(challenge_id=challenge_id)
        
        return query.order_by(ContainerFlagAttempt.timestamp.desc()).all()
