pipeline {
    agent any
    environment {
        VENV_DIR = 'venv'
        DOCKER_IMAGE = 's3csys/amivault:latest'
        FLASK_APP_PORT = '5310'
        SERVER_IP = 'your.server.ip.address'
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
                    pytest test_app.py 
                '''
            }
        }

        stage(Build Docker image) {
            sh '''
                docker build -t ${DOCKER_IMAGE}
            '''
        }
    }

    post {
        always {
            // Clean up workspace
            cleanWs()
        }
        success {
            // Notify success
            echo 'Deployment successful!'
        }
        failure {
            // Notify failure
            echo 'Deployment failed!'
        }
    }
}