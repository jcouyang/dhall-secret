{-# LANGUAGE FlexibleContexts #-}
module Dhall.Secret.Aws where

import Data.Typeable (Typeable)
import         qualified  Amazonka
import           System.IO                (stdout)

awsRun ::  (Amazonka.AWSRequest a, Typeable a, Typeable (Amazonka.AWSResponse a)) => a -> IO (Amazonka.AWSResponse a)
awsRun cmd = do
  logger <- Amazonka.newLogger Amazonka.Info stdout
  discover <- Amazonka.newEnv Amazonka.discover
  Amazonka.runResourceT $ Amazonka.send (discover { Amazonka.logger =logger}) cmd
