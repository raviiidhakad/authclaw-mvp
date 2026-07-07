output "msk_security_group_id" { value = aws_security_group.msk.id }
output "msk_bootstrap_brokers" {
  value = var.serverless ? (
    length(aws_msk_serverless_cluster.main) > 0
    ? "serverless-iam:${aws_msk_serverless_cluster.main[0].cluster_name}"
    : ""
    ) : (
    length(aws_msk_cluster.main) > 0
    ? aws_msk_cluster.main[0].bootstrap_brokers_sasl_iam
    : ""
  )
}
