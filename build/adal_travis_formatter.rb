
class TravisFormatter < XCPretty::Simple
	
	def open_fold(text)
		return if text == @open_fold
		close_fold(@open_fold) if @open_fold
		print "travis_fold:start:#{text}\n"
		@open_fold = text
		
		at_exit do
			close_fold(@open_fold) if @open_fold
		end
	end

	def close_fold(text)
		print "travis_fold:end:#{text}\n"
		@open_fold = nil
	end

  	def format_build_target(target, project, configuration)
    	open_fold(fold_name("Build", target))
    	@current_target = target
    	super
  	end

  	def format_analyze_target(target, project, configuration)
    	open_fold(fold_name("Analyze", target))
    	super
  	end

  	def format_clean_target(target, project, configuration)
    	open_fold(fold_name("Clean", target))
    	super
  	end

  	def format_test_run_started(name)
    	open_fold(fold_name("Test", @current_target))
    	super
  	end

  	def format_test_run_finished(name, time)
    	close_fold(fold_name("Test", @current_target))
    	super
  	end

  	def scrub(text)
    	text.gsub(/\s/,"_").split(".").first
  	end
  
  	def fold_name(action, target)
  		task = ENV["ADAL_TRAVIS_BUILD_TASK"]
  		target = scrub(target)
  		"#{action}_#{task}_#{target}"
  	end
  	
  	

end

TravisFormatter
