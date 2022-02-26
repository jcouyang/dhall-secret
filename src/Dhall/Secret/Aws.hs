module Dhall.Secret.Aws where

import           Control.Lens
import           Data.Text                (pack)
import           Network.AWS              (Credentials (Discover),
                                           HasEnv (envLogger),
                                           LogLevel (Debug, Info), envRegion,
                                           newEnv, newLogger, runAWS,
                                           runResourceT)
import           Network.AWS.Data         (fromText)
import           System.Environment.Blank (getEnv)
import           System.IO                (stdout)

awsRun cmd = do
  logger <- newLogger Info stdout
  discover <- newEnv Discover
  defaultRegion <- getEnv "AWS_REGION"
  runResourceT $ runAWS (case (hush . fromText . pack) =<< defaultRegion of
    Nothing     -> discover & envLogger .~ logger
    Just region -> discover & envRegion .~ region & envLogger .~ logger)
    cmd
  where
    hush (Left _)  = Nothing
    hush (Right x) = Just x
