module Dhall.Secret.Aws where

import           Control.Lens             ((&), (.~))
import           Data.Text                (pack)
import           Network.AWS              (AWS, Credentials (Discover),
                                           HasEnv (envLogger), LogLevel (Info),
                                           envRegion, newEnv, newLogger, runAWS,
                                           runResourceT)
import           Network.AWS.Data         (fromText)
import           System.Environment.Blank (getEnv)
import           System.IO                (stdout)

awsRun :: Network.AWS.AWS b -> IO b
awsRun cmd = do
  logger <- Network.AWS.newLogger Network.AWS.Info stdout
  discover <- Network.AWS.newEnv Network.AWS.Discover
  defaultRegion <- getEnv "AWS_REGION"
  Network.AWS.runResourceT $ Network.AWS.runAWS (case (hush . fromText . pack) =<< defaultRegion of
    Nothing     -> discover & Network.AWS.envLogger .~ logger
    Just region -> discover & Network.AWS.envRegion .~ region & Network.AWS.envLogger .~ logger)
    cmd
  where
    hush (Left _)  = Nothing
    hush (Right x) = Just x
