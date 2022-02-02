module Aws where

import           Control.Lens
import           Network.AWS  (Credentials (Discover), HasEnv (envLogger),
                               LogLevel (Debug, Info), newEnv, newLogger,
                               runAWS, runResourceT)
import           System.IO    (stdout)

awsRun cmd = do
  env <- newEnv Discover
  logger <- newLogger Debug stdout
  runResourceT $ runAWS (env & envLogger .~ logger) cmd
