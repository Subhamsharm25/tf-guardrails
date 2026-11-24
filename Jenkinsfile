// Declarative pipeline: each stage calls ci.py, the same script GitHub Actions runs.
// Agent needs Python 3.11+, terraform and Docker (Linux or Windows agent).

def ci(String stages) {
  if (isUnix()) { sh "${env.PY} ci.py ${stages}" } else { bat "${env.PY} ci.py ${stages}" }
}

pipeline {
  agent any
  options {
    timestamps()
    timeout(time: 30, unit: 'MINUTES')
    buildDiscarder(logRotator(numToKeepStr: '20'))
  }
  stages {
    stage('Setup') {
      steps {
        script {
          env.PY = isUnix() ? '.venv/bin/python' : '.venv\\Scripts\\python.exe'
          if (isUnix()) {
            sh 'python3 -m venv .venv && .venv/bin/python -m pip install -q -e ".[dev]"'
          } else {
            bat 'python -m venv .venv && .venv\\Scripts\\python.exe -m pip install -q -e ".[dev]"'
          }
        }
      }
    }
    stage('Lint + unit')     { steps { script { ci('lint unit') } } }
    stage('Terraform plans') { steps { script { ci('plan') } } }
    stage('Policy gate')     { steps { script { ci('policy') } } }
    stage('Image')           { steps { script { ci('build scan container') } } }
  }
  post {
    always {
      junit allowEmptyResults: true, testResults: 'reports/*.xml'
      archiveArtifacts allowEmptyArchive: true, artifacts: 'reports/**, examples/**/plan.json'
    }
  }
}
