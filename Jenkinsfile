pipeline {
    agent any
    environment {
        VENV_DIR = 'venv'
        DOCKER_IMAGE = 's3csys/amivault:latest'
        FLASK_APP_PORT = '5000'
        SERVER_IP = '30.30.30.25'
    }
    triggers {
        pollSCM('H/2 * * * *')  
    }
    stages {
        stage('Clone') {
            steps {
                git url: 'https://github.com/s3csys/amivault.git', branch: 'main'
            }
        }

        stage('Set Up VENV') {
            steps {
                sh 'python3 -m venv ${VENV_DIR}'
            }
        }

        stage('Dependicies') {
            steps {
                sh '''
                    source ${VENV_DIR}/bin/activate
                    pip install -r requirements.txt
                '''
            }
        }

        stage('Test') {
            steps {
                sh '''
                    source ${VENV_DIR}/bin/activate
                    pytest test_app.py --junitxml=test-results.xml
                '''
            }
        }

        stage('Deployment') {
            steps{
                sshagent([]) {
                    sh '''
                    ssh -o StrictHostKeyChecking=no root@20.20.20.25 << EOf
                    python3 -m venv ${VENV_DIR}
                    source ${VENV_DIR}/bin/activate
                    python3 helper.py --recreate-db
                    python3 
                    EOF
                    '''
                }
            }
        }
    }

    post {
        always {
            // Clean up workspace
            cleanWs()
        }
        success {
            // Notify success
            echo "Deployment successful. The APIVAULT is available at http://${SERVER_IP}:${FLASK_APP_PORT}/"
        }
        failure {
            // Notify failure
            echo 'Deployment failed!'
        }
    }
}