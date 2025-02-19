resource "aws_kms_key" "aws_backup_key" {
  description             = format("%s-AWSBackupKMSKey",var.namePrefix)
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_backup_vault_notifications" "backup" {
  backup_vault_name   = aws_backup_vault.backup-vault.name
  sns_topic_arn       = var.notifications_arn  #aws_sns_topic.system_alarms["backups"].arn
  backup_vault_events = ["BACKUP_JOB_FAILED"]#["BACKUP_JOB_STARTED", "BACKUP_JOB_COMPLETED", "BACKUP_JOB_SUCCESSFUL", "BACKUP_JOB_FAILED"]
}

resource "aws_backup_vault" "backup-vault" {
  name        = format("%s-backupVault",var.namePrefix)
  kms_key_arn = aws_kms_key.aws_backup_key.arn
  tags = {
    Role = "backup-vault"
  }
}

resource "aws_backup_plan" "backup-plan" {
  for_each =  { for k, v in var.backups :  k => v if lookup(v,"enabled",true) != false } 

  name = format("%s-%s-plan",var.namePrefix,each.value.name)

  dynamic "rule" {
    for_each = each.value.rules
    content {
      rule_name                = rule.value.name
      target_vault_name        = aws_backup_vault.backup-vault.name
      schedule                 = rule.value.schedule
      start_window             = lookup(rule.value, "start_window", 60)
      completion_window        = lookup(rule.value, "completion_window", 240)
      enable_continuous_backup = lookup(rule.value, "enable_continuous_backup", false)
      recovery_point_tags = {
        Backup_Rule  = format("%s-%s-plan-%s",var.namePrefix,each.value.name,rule.value.name)
        Created_By = "aws-backup"
        Backup_plan = format("%s-%s-plan",var.namePrefix,each.value.name)
      }

      dynamic "copy_action" {
        for_each = lookup(rule.value,"copy_action",[])
        content {
          destination_vault_arn = copy_action.value.destination_vault_arn
          lifecycle {
            cold_storage_after = copy_action.value.cold_storage_after
            delete_after       = copy_action.value.delete_after
          }
        }              
      }
      lifecycle {
        delete_after = rule.value.delete_after
      }
    }
  }

  dynamic "advanced_backup_setting" {
    for_each =  lookup(each.value,"vss_enabled",false) != false ? { "enabled" = "enabled" } : {}
    content {
      backup_options = {
        WindowsVSS = "enabled"
      }
      resource_type = "EC2"
    }
  }
}

resource "aws_backup_selection" "backup-selection" {
  for_each =  { for k, v in var.backups :  k => v if lookup(v,"enabled",true) != false } 

  iam_role_arn = aws_iam_role.aws-backup-service-role.arn
  name         = format("%s-%s-selection",var.namePrefix,each.value.name)
  plan_id      = aws_backup_plan.backup-plan[each.key].id
  dynamic "selection_tag" {
    for_each = each.value.tags
    content {
      type  = "STRINGEQUALS"
      key   = selection_tag.key
      value = selection_tag.value
    }
  }
}

/* Roles for taking AWS Backups */
resource "aws_iam_role" "aws-backup-service-role" {
  name               = format("%s-AWSBackupServiceRole",var.namePrefix)
  description        = "Allows the AWS Backup Service to take scheduled backups"
  assume_role_policy = data.aws_iam_policy_document.aws-backup-service-assume-role-policy.json
}

resource "aws_iam_role_policy_attachment" "aws-backup-policy-backup" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
  role       = aws_iam_role.aws-backup-service-role.name
}

resource "aws_iam_role_policy_attachment" "aws-backup-policy-restore" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
  role       = aws_iam_role.aws-backup-service-role.name
}

resource "aws_iam_role_policy_attachment" "aws-backup-policy-s3backup" {
  policy_arn = "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Backup"
  role       = aws_iam_role.aws-backup-service-role.name
}

resource "aws_iam_role_policy_attachment" "aws-backup-policy-s3restore" {
  policy_arn = "arn:aws:iam::aws:policy/AWSBackupServiceRolePolicyForS3Restore"
  role       = aws_iam_role.aws-backup-service-role.name
}



# resource "aws_iam_role_policy" "backup-service-aws-backup-role-policy" {
#   policy = data.aws_iam_policy.aws-backup-service-policy.policy
#   role   = aws_iam_role.aws-backup-service-role.name
# }

# resource "aws_iam_role_policy" "restore-service-aws-backup-role-policy" {
#   policy = data.aws_iam_policy.aws-restore-service-policy.policy
#   role   = aws_iam_role.aws-backup-service-role.name
# }

# resource "aws_iam_role_policy" "backup-service-pass-role-policy" {
#   policy = data.aws_iam_policy_document.example-pass-role-policy-doc.json
#   role   = aws_iam_role.aws-backup-service-role.name
# }

data "aws_iam_policy_document" "aws-backup-service-assume-role-policy" {
  statement {
    sid     = "AssumeServiceRole"
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }
}

# /* The policies that allow the backup service to take backups and restores */
# data "aws_iam_policy" "aws-backup-service-policy" {
#   arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
# }

# data "aws_iam_policy" "aws-restore-service-policy" {
#   arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
# }

# data "aws_caller_identity" "current_account" {}

/* Needed to allow the backup service to restore from a snapshot to an EC2 instance
 See https://stackoverflow.com/questions/61802628/aws-backup-missing-permission-iampassrole */
# data "aws_iam_policy_document" "example-pass-role-policy-doc" {
#   statement {
#     sid       = "PassRole"
#     actions   = ["iam:PassRole"]
#     effect    = "Allow"
#     resources = ["arn:aws:iam::${data.aws_caller_identity.current_account.account_id}:role/*"]
#   }
# }

